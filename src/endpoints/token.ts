import { onRequest } from 'firebase-functions/v2/https';
import {
  DefaultClientCredentialFetcherProvider,
  TokenEndpoint,
} from 'oauth2-nodejs';
import { CustomGrantHandlerProvider } from './../granttype';
import { CloudFirestoreDataHandlerFactory } from '../data';
import { RequestWrapper } from '../models/request_wrapper';
import {
  sendFailureIndicator,
  sendSuccessIndicator,
  cloudLoggingMetadata,
  getProjectId
} from '../utils/sliLogger';
import cors from 'cors';
import express from 'express';

// ✅ Create Express app for proper middleware handling
const tokenApp = express();
tokenApp.use(cors({ origin: true }));

// ✅ Define route
tokenApp.post('/', async (req, res) => {
  // SLI Logger metadata
  const metadataResourceType = "Firebase Auth";
  const metadataAction = "Token Registration";
  const metadataCriticalUserJourney = "SSO";
  const metadata = cloudLoggingMetadata(
    getProjectId(),
    metadataResourceType,
    metadataAction,
    metadataCriticalUserJourney,
  );

  try {
    const request = new RequestWrapper(req);
    const tokenEndpoint = new TokenEndpoint();
    const clientCredentialFetcherProvider = new DefaultClientCredentialFetcherProvider();

    tokenEndpoint.grantHandlerProvider = new CustomGrantHandlerProvider(clientCredentialFetcherProvider);
    tokenEndpoint.clientCredentialFetcherProvider = clientCredentialFetcherProvider;
    tokenEndpoint.dataHandlerFactory = new CloudFirestoreDataHandlerFactory();

    const tokenEndpointResponse = await tokenEndpoint.handleRequest(request);

    res.status(tokenEndpointResponse.code)
       .contentType("application/json; charset=UTF-8")
       .send(tokenEndpointResponse.body);

    sendSuccessIndicator(metadata, "Successfully provided token", metadataResourceType, metadataAction);
  } catch (error) {
    console.error("Token endpoint error:", error);

    res.status(500).json({ error: "Token generation failed", details: error.message || error });

    sendFailureIndicator(metadata, "Failed to provide token", metadataResourceType, metadataAction);
  }
});

// ✅ Handle other methods
tokenApp.all('*', (req, res) => {
  res.status(405).send("Method Not Allowed");

  sendFailureIndicator(
    cloudLoggingMetadata(getProjectId(), "Firebase Auth", "Token Registration", "SSO"),
    "Failed to provide token, method not allowed",
    "Firebase Auth",
    "Token Registration"
  );
});

// ✅ Export as Firebase v2 function
export const token = onRequest(tokenApp);
