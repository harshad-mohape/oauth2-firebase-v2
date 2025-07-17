import { onSchedule } from "firebase-functions/v2/scheduler";
import { logger } from "firebase-functions";
import * as admin from "firebase-admin";

if (!admin.apps.length) {
  admin.initializeApp();
}

// ✅ Garbage collection function
export function garbageCollection(expiry = 2592000000, interval = "every 24 hours") {
  return onSchedule(
    {
      schedule: interval,
      timeZone: "UTC", // Change if needed
      region: "us-central1", // Update region if needed
      memory: "256MiB",
    },
    async () => {
      const db = admin.firestore();

      const now = Date.now();
      const threshold = now - expiry;

      logger.info("Running Garbage Collection", { now, threshold });

      try {
        const oldTokens = await db
          .collection("oauth2_access_tokens")
          .where("created_on", "<=", threshold)
          .get();

        if (oldTokens.empty) {
          logger.info("No old tokens found.");
          return;
        }

        const deletePromises: Promise<FirebaseFirestore.WriteResult>[] = [];

        for (const tokenDoc of oldTokens.docs) {
          const data = tokenDoc.data();
          if (data.created_on && data.expires_in && now > data.created_on + data.expires_in) {
            logger.info(`Deleting token: ${tokenDoc.id}`, data);
            deletePromises.push(tokenDoc.ref.delete());
          }
        }

        await Promise.all(deletePromises);
        logger.info(`Deleted ${deletePromises.length} expired tokens.`);
      } catch (error) {
        logger.error("Error during garbage collection", error);
      }
    }
  );
}
