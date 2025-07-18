import { onRequest } from "firebase-functions/v2/https";
import * as admin from "firebase-admin";
import express, { Request, Response, Application } from "express";
import * as qs from "qs";
import cors from "cors";
import { RequestWrapper } from "../models";
import { Crypto, Navigation, processConsent } from "../utils";
import { CloudFirestoreClients } from "../data";
import {
  sendFailureIndicator,
  sendSuccessIndicator,
  cloudLoggingMetadata,
  getProjectId,
} from "../utils/sliLogger";

class AuthenticationApp {
  static create(authenticationUrl: string): Application {
    const authenticationApp = express();

    // ✅ Correct CORS usage
    authenticationApp.use(cors({ origin: true }));

    // ✅ Handle GET routes
    const authenticationGet = (req: Request, resp: Response) => {
      const request = new RequestWrapper(req);
      const authToken = request.getParameter("auth_token");

      const payload = { authToken };
      const strippedUrl = authenticationUrl.split("?")[0];
      const urlWithPayload = `${strippedUrl}?${qs.stringify(payload)}`;

      resp.redirect(urlWithPayload);
    };

    authenticationApp.get("/", authenticationGet);
    authenticationApp.get("/authentication", authenticationGet);

    // ✅ Handle POST routes
    const authenticationPost = async (req: Request, resp: Response) => {
      const request = new RequestWrapper(req);
      const encryptedAuthToken = request.getParameter("auth_token")!;
      const idTokenString = request.getParameter("id_token")!;
      const success = request.getParameter("success");

      const metadataResourceType = "Firebase Auth";
      const metadataAction = "Authentication";
      const metadataCriticalUserJourney = "SSO";
      const metadata = cloudLoggingMetadata(
        getProjectId(),
        metadataResourceType,
        metadataAction,
        metadataCriticalUserJourney
      );

      try {
        const authToken = JSON.parse(Crypto.decrypt(encryptedAuthToken));

        if (success === "true") {
          const idToken = await admin.auth().verifyIdToken(idTokenString);

          if (idToken.aud === process.env.GCLOUD_PROJECT) {
            const client = await CloudFirestoreClients.fetch(authToken["client_id"]);

            if (client?.implicitConsent) {
              const payload = await processConsent(
                resp,
                { action: "allow", authToken, userId: idToken.sub },
                { redirect: !client?.browserRedirect }
              );

              sendSuccessIndicator(metadata, "Browser redirect after implicit consent", metadataResourceType, metadataAction);
              return resp.json(payload);
            } else {
              const encryptedUserId = Crypto.encrypt(idToken.sub);
              return Navigation.redirect(resp, "/authorize/consent", {
                auth_token: encryptedAuthToken,
                user_id: encryptedUserId,
              });
            }
          }
        }

        // Default failure behavior
        if (success !== "true") {
          if (authToken && authToken["redirect_uri"]) {
            Navigation.redirect(resp, authToken["redirect_uri"], { error: "access_denied" });
          } else {
            resp.status(400).json({ error: "access_denied" });
          }

          sendFailureIndicator(metadata, "Authentication failed", metadataResourceType, metadataAction);
        }
      } catch (error) {
        console.error("Authentication error:", error);
        resp.status(500).json({ error: "Authentication error", details: error.message });

        sendFailureIndicator(metadata, "Authentication exception", metadataResourceType, metadataAction);
      }
    };

    authenticationApp.post("/", authenticationPost);
    authenticationApp.post("/authentication", authenticationPost);

    return authenticationApp;
  }
}

// ✅ Firebase v2 wrapper
export function customAuthentication(loginUri: string) {
  return onRequest(AuthenticationApp.create(loginUri));
}
