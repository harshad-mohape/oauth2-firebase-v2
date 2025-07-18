import { Request } from "oauth2-nodejs";
import * as express from "express";

export class RequestWrapper implements Request {
  private _original: express.Request;

  constructor(original: express.Request) {
    if (!original) {
      throw new Error("RequestWrapper received undefined request");
    }
    this._original = original;

    // Ensure critical properties are defined
    this._original.headers = this._original.headers || {};
    this._original.query = this._original.query || {};
    this._original.body = this._original.body || {};
  }

  getHeader(name: string): string {
    try {
      return this._original.get?.(name) || "";
    } catch {
      return "";
    }
  }

  getParameter(name: string): string | undefined {
    return (this._original.query[name] as string) || (this._original.body[name] as string);
  }

  getParameterMap(): Map<string, string> {
    const result = new Map<string, string>();

    // Query params
    for (const key in this._original.query) {
      const val = this._original.query[key];
      if (typeof val === "string") {
        result.set(key, val);
      }
    }

    // Body params (overwriting any from query)
    for (const key in this._original.body) {
      const val = this._original.body[key];
      if (typeof val === "string") {
        result.set(key, val);
      }
    }

    return result;
  }
}
