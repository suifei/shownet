import type { HeaderEntry } from "./types";

export type RequestCodeTemplate = "curl" | "httpie" | "python" | "java" | "fetch" | "axios" | "go";

export const requestCodeTemplates: ReadonlyArray<{ id: RequestCodeTemplate; label: string }> = [
  { id: "python", label: "Python (requests)" },
  { id: "java", label: "Java (HttpClient)" },
  { id: "fetch", label: "JavaScript (Fetch)" },
  { id: "axios", label: "TypeScript (Axios)" },
  { id: "go", label: "Go (net/http)" },
  { id: "curl", label: "cURL" },
  { id: "httpie", label: "HTTPie" },
];

export interface RequestCodeInput {
  method: string;
  url: string;
  headers: HeaderEntry[];
  body?: string;
}

function activeHeaders(headers: HeaderEntry[]) {
  // Blank rows are editor placeholders. Every entered credential remains in output; HTTP/2 pseudo headers are represented by the URL and method instead.
  return headers
    .filter((header) => header.name.trim() && !header.name.trim().startsWith(":"))
    .map((header) => ({ ...header, name: header.name.trim() }));
}

function quote(value: string) {
  return JSON.stringify(value);
}

function shellQuote(value: string) {
  return `'${value.replace(/'/g, `"'"'`)}'`;
}

function objectLiteral(headers: HeaderEntry[]) {
  return `{\n${headers.map((header) => `  ${quote(header.name)}: ${quote(header.value)},`).join("\n")}\n}`;
}

function isDuplicateHeader(headers: HeaderEntry[]) {
  const names = new Set<string>();
  return headers.some((header) => {
    const name = header.name.toLowerCase();
    if (names.has(name)) return true;
    names.add(name);
    return false;
  });
}

function curlCode(method: string, url: string, headers: HeaderEntry[], body: string) {
  const parts = ["curl", "--request", shellQuote(method), shellQuote(url)];
  for (const header of headers) parts.push("--header", shellQuote(`${header.name}: ${header.value}`));
  if (body) parts.push("--data-raw", shellQuote(body));
  return parts.join(" ");
}

function httpieCode(method: string, url: string, headers: HeaderEntry[], body: string) {
  const parts = ["http", method, shellQuote(url)];
  for (const header of headers) parts.push(shellQuote(`${header.name}:${header.value}`));
  if (body) parts.push("<<<", shellQuote(body));
  return parts.join(" ");
}

function pythonCode(method: string, url: string, headers: HeaderEntry[], body: string) {
  const headerNotes = isDuplicateHeader(headers)
    ? "\n# requests keeps the last value for duplicate header names.\n"
    : "\n";
  return `import requests\n\nheaders = ${objectLiteral(headers)}${headerNotes}\nresponse = requests.request(\n    method=${quote(method)},\n    url=${quote(url)},\n    headers=headers,${body ? `\n    data=${quote(body)},` : ""}\n)\nresponse.raise_for_status()\nprint(response.text)`;
}

function javaCode(method: string, url: string, headers: HeaderEntry[], body: string) {
  const headerLines = headers.map((header) => `    .header(${quote(header.name)}, ${quote(header.value)})`).join("\n");
  const bodyPublisher = body
    ? `HttpRequest.BodyPublishers.ofString(${quote(body)}, StandardCharsets.UTF_8)`
    : "HttpRequest.BodyPublishers.noBody()";
  return `import java.net.URI;\nimport java.net.http.HttpClient;\nimport java.net.http.HttpRequest;\nimport java.net.http.HttpResponse;\nimport java.nio.charset.StandardCharsets;\n\npublic class Main {\n  public static void main(String[] args) throws Exception {\n    HttpClient client = HttpClient.newHttpClient();\n    HttpRequest request = HttpRequest.newBuilder()\n    .uri(URI.create(${quote(url)}))${headerLines ? `\n${headerLines}` : ""}\n    .method(${quote(method)}, ${bodyPublisher})\n    .build();\n\n    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());\n    System.out.println(response.statusCode());\n    System.out.println(response.body());\n  }\n}`;
}

function fetchCode(method: string, url: string, headers: HeaderEntry[], body: string) {
  const headerLines = headers.map((header) => `headers.append(${quote(header.name)}, ${quote(header.value)});`).join("\n");
  return `const headers = new Headers();\n${headerLines}\n\nconst response = await fetch(${quote(url)}, {\n  method: ${quote(method)},\n  headers,${body ? `\n  body: ${quote(body)},` : ""}\n});\n\nconsole.log(response.status);\nconsole.log(await response.text());`;
}

function axiosCode(method: string, url: string, headers: HeaderEntry[], body: string) {
  const headerLines = headers.map((header) => `headers[${quote(header.name)}] = ${quote(header.value)};`).join("\n");
  const duplicateNote = isDuplicateHeader(headers) ? "\n// Axios uses the last value for duplicate header names.\n" : "\n";
  return `import axios from "axios";\n\nconst headers: Record<string, string> = {};\n${headerLines}${duplicateNote}\nconst response = await axios({\n  method: ${quote(method.toLowerCase())},\n  url: ${quote(url)},\n  headers,${body ? `\n  data: ${quote(body)},` : ""}\n});\n\nconsole.log(response.status);\nconsole.log(response.data);`;
}

function goCode(method: string, url: string, headers: HeaderEntry[], body: string) {
  const headerLines = headers.map((header) => `\treq.Header.Add(${quote(header.name)}, ${quote(header.value)})`).join("\n");
  return `package main\n\nimport (\n\t"fmt"\n\t"io"\n\t"net/http"\n\t"strings"\n)\n\nfunc main() {\n\treq, err := http.NewRequest(${quote(method)}, ${quote(url)}, strings.NewReader(${quote(body)}))\n\tif err != nil { panic(err) }${headerLines ? `\n${headerLines}` : ""}\n\n\tresponse, err := http.DefaultClient.Do(req)\n\tif err != nil { panic(err) }\n\tdefer response.Body.Close()\n\tbody, err := io.ReadAll(response.Body)\n\tif err != nil { panic(err) }\n\tfmt.Println(response.StatusCode)\n\tfmt.Println(string(body))\n}`;
}

export function generateRequestCode(input: RequestCodeInput, template: RequestCodeTemplate) {
  const method = input.method.trim().toUpperCase() || "GET";
  const url = input.url.trim();
  const headers = activeHeaders(input.headers);
  const body = input.body ?? "";

  if (template === "curl") return curlCode(method, url, headers, body);
  if (template === "httpie") return httpieCode(method, url, headers, body);
  if (template === "python") return pythonCode(method, url, headers, body);
  if (template === "java") return javaCode(method, url, headers, body);
  if (template === "fetch") return fetchCode(method, url, headers, body);
  if (template === "axios") return axiosCode(method, url, headers, body);
  return goCode(method, url, headers, body);
}
