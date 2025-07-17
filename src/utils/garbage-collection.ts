import { onSchedule } from "firebase-functions/v2/scheduler"; // Updated import
import * as admin from "firebase-admin";

// Updated function definition
export function garbageCollection(expiry = 2592000000, interval = "every 24 hours") {
  return onSchedule(interval, async () => {
    const db = admin.firestore();

    const now = new Date().getTime();
    const threshold = now - expiry;

    console.log("Now", now, "Threshold", threshold); // Updated logging
    const oldTokens = await db
      .collection("oauth2_access_tokens")
      .where("created_on", "<=", threshold)
      .get();

    oldTokens.forEach(async (tokenSnapshot) => {
      const data = tokenSnapshot.data();
      console.log(data.oauth_info_id); // Updated logging
      if (now > data.created_on + data.expires_in) {
        await db
          .collection("oauth2_access_tokens")
          .doc(tokenSnapshot.id)
          .delete();
      }
    });
  });
}
