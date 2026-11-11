import { createServer } from "node:http";
import { timingSafeEqual, sign, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";

const html = await readFile(new URL("./todo.html", import.meta.url));
const {
  SHEET_ID,
  GOOGLE_APPLICATION_CREDENTIALS,
  TODO_PASSWORD,
  PORT = "3000",
  HOST = "127.0.0.1"
} = process.env;

const credentials = GOOGLE_APPLICATION_CREDENTIALS
  ? JSON.parse(await readFile(GOOGLE_APPLICATION_CREDENTIALS, "utf8"))
  : null;

const idPattern = /^[a-zA-Z0-9_-]{1,64}$/;
let token;
let expiresAt = 0;

function send(response, status, data) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8"
  });
  response.end(JSON.stringify(data));
}

async function accessToken() {
  if (token && Date.now() < expiresAt) return token;

  const now = Math.floor(Date.now() / 1000);
  const encode = value =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  const endpoint = "https://oauth2.googleapis.com/token";

  const claims = encode({
    iss: credentials.client_email,
    scope: "https://www.googleapis.com/auth/spreadsheets",
    aud: endpoint,
    iat: now,
    exp: now + 3600
  });

  const unsigned = encode({ alg: "RS256", typ: "JWT" }) + "." + claims;
  const signature = sign("RSA-SHA256", Buffer.from(unsigned), credentials.private_key);

  const response = await fetch(endpoint, {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: unsigned + "." + signature.toString("base64url")
    }),
    signal: AbortSignal.timeout(10000)
  });

  if (!response.ok) {
    throw new Error("Google authentication failed (" + response.status + ").");
  }

  const result = await response.json();
  token = result.access_token;
  expiresAt = Date.now() + Math.max(0, result.expires_in - 60) * 1000;
  return token;
}

async function sheets(range, { method = "GET", values } = {}) {
  const endpoint = "https://sheets.googleapis.com/v4/spreadsheets/" +
    SHEET_ID + "/values/" + encodeURIComponent(range);

  let suffix = "?valueInputOption=RAW";
  if (method === "GET") {
    suffix = "?valueRenderOption=UNFORMATTED_VALUE";
  } else if (method === "POST") {
    suffix = ":append?valueInputOption=RAW&insertDataOption=INSERT_ROWS";
  }

  const response = await fetch(endpoint + suffix, {
    method,
    headers: {
      Authorization: "Bearer " + await accessToken(),
      "Content-Type": "application/json"
    },
    body: values === undefined ? undefined : JSON.stringify({ values }),
    signal: AbortSignal.timeout(10000)
  });

  if (!response.ok) {
    throw new Error("Google Sheets request failed (" + response.status + ").");
  }

  return response.json();
}

async function tasks() {
  const { values = [] } = await sheets("Tasks!A2:C");
  const results = [];
  const ids = new Set();

  for (const [index, [title, done, rawId]] of values.entries()) {
    const name = String(title ?? "").trim();
    if (!name) continue;

    const id = String(rawId ?? "").trim();
    if (!idPattern.test(id) || ids.has(id)) {
      throw new Error(
        "Give each task a unique ID in column C, using letters, digits, dashes, or underscores."
      );
    }

    ids.add(id);
    results.push({ id, name, done: done === true, row: index + 2 });
  }

  return results;
}

function authorized(request) {
  if (!TODO_PASSWORD) return true;

  const expected = Buffer.from(
    "Basic " + Buffer.from("todo:" + TODO_PASSWORD).toString("base64")
  );
  const received = Buffer.from(request.headers.authorization || "");

  return received.length === expected.length &&
    timingSafeEqual(received, expected);
}

const server = createServer(async (request, response) => {
  response.setHeader("Cache-Control", "no-store");

  const path = new URL(request.url, "http://localhost").pathname;
  const match = path.match(/^\/todo\/api\/tasks\/([^/]+)$/);

  if (path !== "/todo" && path !== "/todo/" && path !== "/todo/api/tasks" && !match) {
    return send(response, 404, { error: "Page not found." });
  }

  if (!authorized(request)) {
    response.setHeader("WWW-Authenticate", 'Basic realm="To-do"');
    return send(response, 401, { error: "Sign in to view your tasks." });
  }

  if (request.method === "GET" && (path === "/todo" || path === "/todo/")) {
    response.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    return response.end(html);
  }

  if (!credentials || !SHEET_ID || !/^[a-zA-Z0-9_-]+$/.test(SHEET_ID)) {
    return send(response, 503, {
      error: "Set SHEET_ID and GOOGLE_APPLICATION_CREDENTIALS to load tasks."
    });
  }

  try {
    if (request.method === "GET" && path === "/todo/api/tasks") {
      const results = await tasks();
      return send(response, 200, results.map(({ id, name, done }) => ({
        id, name, done
      })));
    }

    const adding = request.method === "POST" && path === "/todo/api/tasks";
    const updating = request.method === "PATCH" && match && idPattern.test(match[1]);

    if (!adding && !updating) {
      return send(response, 405, { error: "Unsupported request." });
    }

    if (request.headers["content-type"] !== "application/json") {
      return send(response, 415, { error: "Expected JSON." });
    }

    let raw = "";
    request.setEncoding("utf8");

    for await (const chunk of request) {
      raw += chunk;
      if (Buffer.byteLength(raw) > 8192) {
        return send(response, 413, { error: "Request too large." });
      }
    }

    let body;
    try {
      body = JSON.parse(raw);
    } catch {
      return send(response, 400, { error: "Invalid JSON." });
    }

    if (adding) {
      const name = typeof body?.name === "string" ? body.name.trim() : "";

      if (!name || name.length > 500) {
        return send(response, 400, {
          error: "Enter a task between 1 and 500 characters."
        });
      }

      const task = { id: randomUUID(), name, done: false };

      await sheets("Tasks!A1:A", {
        method: "POST",
        values: [[task.name, task.done, task.id]]
      });

      return send(response, 201, task);
    }

    if (typeof body?.done !== "boolean") {
      return send(response, 400, { error: "Expected a completion state." });
    }

    const task = (await tasks()).find(item => item.id === match[1]);
    if (!task) return send(response, 404, { error: "Task not found." });

    await sheets("Tasks!B" + task.row, {
      method: "PUT",
      values: [[body.done]]
    });

    return send(response, 200, { done: body.done });
  } catch (error) {
    console.error(error.message);
    return send(response, 502, {
      error: "Could not sync with Google Sheets. Check the connection and task IDs, then try again."
    });
  }
});

if (HOST !== "127.0.0.1" && HOST !== "::1" && !TODO_PASSWORD) {
  throw new Error("Set TODO_PASSWORD before allowing access from other devices.");
}

server.listen(Number(PORT), HOST, () => {
  console.log("To-do page listening on port " + PORT);
});