// Replace publisher() in server.js with this version.
function publisher(req) {
  return !!(
    req.session.user &&
    req.session.user.provider === 'telegram' &&
    ALLOWED.has((req.session.user.username || '').toLowerCase())
  );
}
