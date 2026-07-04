// Boot the Pendo SDK with an anonymous visitor.
// Empty visitor.id lets the SDK resolve from cookies/localStorage if available,
// otherwise it falls back to a new anonymous visitor.
pendo.initialize({
  visitor: {
    id: ''
  }
});

// After sign-in, call pendo.identify() with the authenticated user's data.
// Example (invoke this from your authentication success callback):
//
//   pendo.identify({
//     visitor: {
//       id:      userId,       // REQUIRED — globally unique visitor identifier
//       userId:  userId        // custom attribute from PlanRequest.user_id
//     }
//   });
//
// On sign-out, call:
//
//   pendo.clearSession();
