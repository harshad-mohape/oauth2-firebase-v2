import express from "express";
import { onRequest } from "firebase-functions/v2/https";
import cors from "cors";
import { Request, Response } from "express";
import { RequestWrapper } from "../models";
import { AuthorizationEndpoint } from "oauth2-nodejs";
import { CloudFirestoreDataHandlerFactory } from "../data";
import { Crypto, Navigation } from "../utils";
import {
  sendFailureIndicator,
  sendSuccessIndicator,
  cloudLoggingMetadata,
  getProjectId,
} from "../utils/sliLogger";

class AuthorizeApp {
  static create(authenticationUrl: string): express.Application {
    const app = express();

    app.use(cors({ origin: "*" }));

    app.get("/authorize/entry", async (req: Request, resp: Response) => {
      const request = new RequestWrapper(req);
      const authorizationEndpoint = new AuthorizationEndpoint();

      authorizationEndpoint.dataHandlerFactory =
        new CloudFirestoreDataHandlerFactory();
      authorizationEndpoint.allowedResponseTypes = ["code", "token"];

      const metadataResourceType = "Firebase Auth";
      const metadataAction = "Authorization";
      const metadataCriticalUserJourney = "SSO";
      const metadata = cloudLoggingMetadata(
        getProjectId(),
        metadataResourceType,
        metadataAction,
        metadataCriticalUserJourney
      );

      try {
        const authorizationEndpointResponse =
          await authorizationEndpoint.handleRequest(request);

        if (authorizationEndpointResponse.isSuccess()) {
          const authToken: { [key: string]: any } = {
            client_id: request.getParameter("client_id"),
            redirect_uri: request.getParameter("redirect_uri"),
            response_type: request.getParameter("response_type"),
            scope: request.getParameter("scope"),
            created_at: Date.now(),
          };

          const state = request.getParameter("state");
          if (state) authToken["state"] = state;

          const authTokenString = Crypto.encrypt(JSON.stringify(authToken));

          sendSuccessIndicator(
            metadata,
            "Successfully authorized user, redirecting to /authentication",
            metadataResourceType,
            metadataAction
          );

          Navigation.redirect(resp, authenticationUrl, {
            auth_token: authTokenString,
          });
        } else {
          const error = authorizationEndpointResponse.error;
          console.error(error.toJson());
          resp.contentType("application/json; charset=UTF-8");
          resp.status(error.code).send(error.toJson());

          sendFailureIndicator(
            metadata,
            "Authorization failure",
            metadataResourceType,
            metadataAction
          );
        }
      } catch (error) {
        console.error(error);
        resp.status(500).send(error.toString());
        sendFailureIndicator(
          metadata,
          "Authorization failure",
          metadataResourceType,
          metadataAction
        );
      }
    });

    app.get("/entry", (req: Request, resp: Response) => {
      resp.status(200).send("Entry Point Active");
    });

    return app;
  }
}

// ✅ Export a function that accepts the URI
export function customAuthorize(authUrl: string) {
  return onRequest(AuthorizeApp.create(authUrl));
}
