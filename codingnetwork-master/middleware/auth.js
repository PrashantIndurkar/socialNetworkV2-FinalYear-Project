const jwt = require("jsonwebtoken");
const config = require("config");

module.exports = function(req, res, next) {
  // Get token from header
  const token = req.header("x-auth-token");

  // Check if no token
  if (!token) {
    // 401 : not authorization
    return res.status(401).json({ msg: "No token, authorization denied" });
  }

  // if there's token, need to verify the token whehter it's valid
  try {
    // use jwt.verify to decode the token
    const decoded = jwt.verify(token, config.get("jwtSecret"));
    // if it's a valid token, then send it as req
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ msg: "Token is not valid" });
  }
};
