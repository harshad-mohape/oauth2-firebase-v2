import { Request, Response } from 'express';
const express = require('express');
import { Application } from 'express';
import { onRequest } from "firebase-functions/v2/https"; // Updated import
import { RequestWrapper } from "../models";
import { AuthorizationEndpoint } from "oauth2-nodejs";
import { CloudFirestoreDataHandlerFactory } from "../data";
import { Crypto, Navigation } from "../utils";
const cors = require("cors");
import {
  sendFailureIndicator,
  sendSuccessIndicator,
  cloudLoggingMetadata,
  getProjectId
} from '../utils/sliLogger'

class AuthorizeApp {
  static create(
    providerName: string,
    authenticationUrl: string,
  ): Application {
    const authorizeApp = express();
authorizeApp.use(cors({ origin: "*" }));
const authorizeProvider = async (req: Request, resp: Response) => {
  const request = new RequestWrapper(req);
  const authorizationEndpoint = new AuthorizationEndpoint();
  // functions.logger.log(request) // Removed old logging
  console.log(request); // Using console.log for v2 logging
  authorizationEndpoint.dataHandlerFactory = new CloudFirestoreDataHandlerFactory();
  authorizationEndpoint.allowedResponseTypes = ["code", "token"];

  // SLI Logger
  const metadataResourceType = "Firebase Auth";
  const metadataAction = "Authorization";
  const metadataCriticalUserJourney = "SSO";
  const metadata = cloudLoggingMetadata(
    getProjectId(),
    metadataResourceType,
    metadataAction,
    metadataCriticalUserJourney,
  );

      // functions.logger.info("reqeuest", request); // Removed old logging
      // functions.logger.info("authorizationEndpoint", authorizationEndpoint); // Removed old logging
      console.log("request", request); // Using console.log for v2 logging
      console.log("authorizationEndpoint", authorizationEndpoint); // Using console.log for v2 logging


      try {
        const authorizationEndpointResponse = await authorizationEndpoint.handleRequest(
          request
        );
        // functions.logger.info(authorizationEndpointResponse); // Removed old logging
        console.log(authorizationEndpointResponse); // Using console.log for v2 logging
        if (authorizationEndpointResponse.isSuccess()) {
          const authToken: { [key: string]: any } = {
            client_id: request.getParameter("client_id"),
            redirect_uri: request.getParameter("redirect_uri"),
            response_type: request.getParameter("response_type"),
            scope: request.getParameter("scope"),
            created_at: Date.now(),
          };

          const state = request.getParameter("state");

          if (state) {
            authToken["state"] = state;
          }

          const authTokenString = Crypto.encrypt(JSON.stringify(authToken));

          // SLI Logger
          sendSuccessIndicator(
            metadata,
            "Successfully authorized user, redirecting to /authentication",
            metadataResourceType,
            metadataAction,
          );

          Navigation.redirect(resp, `${authenticationUrl}`, {
            auth_token: authTokenString,
          });
        } else {
          const error = authorizationEndpointResponse.error;
          // functions.logger.error(error.toJson()); // Removed old logging
          console.error(error.toJson()); // Using console.error for v2 logging
          resp.contentType("application/json; charset=UTF-8");
          resp.status(error.code).send(error.toJson());

          // SLI Logger
          sendFailureIndicator(
            metadata,
            "Authorization failure",
            metadataResourceType,
            metadataAction,
          );
        }
      } catch (error) {
        resp.status(500).send(error.toString());

        sendFailureIndicator(
          metadata,
          "Authorization failure",
          metadataResourceType,
          metadataAction,
        );
      }
    };
    authorizeApp.get("/authorize/entry", authorizeProvider);
    authorizeApp.get("/entry", authorizeProvider);
    

    return authorizeApp;
  }
}



export function customAuthorize(authenticationUrl: string) {
  return onRequest( // Updated function definition
    AuthorizeApp.create("Custom", process.env.AUTHENTICATION_URL || ""), // Using environment variable for auth URL
  );
}
