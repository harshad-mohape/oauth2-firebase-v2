import { onRequest } from "firebase-functions/v2/https";
import admin = require("firebase-admin");
const express = require('express');
import * as qs from "qs";
import { Request, Response, Application } from 'express';
const cors = require('cors')();
import { RequestWrapper } from "../models";
import { Crypto, Navigation, processConsent } from "../utils";
import { CloudFirestoreClients } from "../data";
import {
  sendFailureIndicator,
  sendSuccessIndicator,
  cloudLoggingMetadata,
  getProjectId
} from '../utils/sliLogger';

class AuthenticationApp {
  static create(
    providerName: string,
    authenticationUrl: string,
  ): Application {
    const authenticationApp = express();
 authenticationApp.use(cors);

    const authenticationGet = (
      req: Request,
      resp: Response,
    ) => {
      const request = new RequestWrapper(req);
      const authToken = request.getParameter("auth_token");

      const payload = {
        authToken: authToken,
      };

      const strippedUrl = authenticationUrl.split("?")[0];
      const urlWithPayload = `${strippedUrl}?${qs.stringify(payload)}`;

      resp.redirect(urlWithPayload);
    };

    authenticationApp.get("/", authenticationGet);
    authenticationApp.get("/authentication", authenticationGet);
    const authenticationPost = async (
      req: Request,
      resp: Response,
    ) => {
      const request = new RequestWrapper(req);
      const encyptedAuthToken = request.getParameter("auth_token")!;
      const idTokenString = request.getParameter("id_token")!;
      const success = request.getParameter("success");

      // SLI Logger
      const metadataResourceType = "Firebase Auth";
      const metadataAction = "Authentication";
      const metadataCriticalUserJourney = "SSO";
      const metadata = cloudLoggingMetadata(
        getProjectId(),
        metadataResourceType,
        metadataAction,
        metadataCriticalUserJourney,
      );

      const authToken = JSON.parse(
        Crypto.decrypt(request.getParameter("auth_token")!),
      );
      let client;
      if (success === "true") {
        try {
          const idToken = await admin.auth().verifyIdToken(idTokenString);

          if (idToken.aud === process.env.GCLOUD_PROJECT) {
            client = await CloudFirestoreClients.fetch(authToken["client_id"]);

            if (client?.implicitConsent) {
              const payload = await processConsent(
                resp,
                {
                  action: "allow",
                  authToken,
                  userId: idToken.sub,
                },
                { redirect: !client?.browserRedirect },
              );

              // SLI Logger
              sendSuccessIndicator(
                metadata,
                "Browser redirect to avoid CORS",
                metadataResourceType,
                metadataAction,
              );

              return resp.json(payload);
            } else {
              const encryptedUserId = Crypto.encrypt(idToken.sub);

              Navigation.redirect(resp, "/authorize/consent", {
                auth_token: encyptedAuthToken,
                user_id: encryptedUserId,
              });
            }
          }
        } catch (error) {
          // SLI Logger
          sendFailureIndicator(
            metadata,
            "Authentication error",
            metadataResourceType,
            metadataAction,
          );

          return resp.json({error: JSON.stringify(error)})
        }
      }
      if (client?.browserRedirect) {
        // SLI Logger
        sendFailureIndicator(
          metadata,
          "Authentication error",
          metadataResourceType,
          metadataAction,
        );

        return resp.json({
          error: "access_denied",
        });
      }

      Navigation.redirect(resp, authToken["redirect_uri"], {
        error: "access_denied",
      });

      // SLI Logger
      sendFailureIndicator(
        metadata,
        "Authentication error",
        metadataResourceType,
        metadataAction,
      );

      return
    };
    authenticationApp.post("/", authenticationPost);
    authenticationApp.post("/authentication", authenticationPost);
    return authenticationApp;
  }
}

export const customAuthentication = onRequest(
  AuthenticationApp.create("custom", process.env.AUTHENTICATION_URL || ""),
);
