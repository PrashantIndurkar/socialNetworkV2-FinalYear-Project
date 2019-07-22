const express = require("express");
const router = express.Router();
const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("config");
const { check, validationResult } = require("express-validator/check");

const User = require("../../models/Users");

// @route    GET api/users
// @desc     Register user
// @access   Public
router.post(
  "/",
  [
    //express-validator/check
    check("name", "Name is required")
      .not()
      .isEmpty(),
    check("email", "Please include a valid email").isEmail(),
    check(
      "password",
      "Please enter a password with 6 or more characters"
    ).isLength({ min: 6 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    try {
      // See if user exists
      let user = await User.findOne({ email });
      if (user) {
        return res
          .status(400)
          .json({ errors: [{ msg: "User already exists" }] });
      }

      // Get users gravatar
      const avatar = gravatar.url(email, {
        //d:size, r: rating, d:default
        s: "200",
        r: "pg",
        d: "mm"
      });

      // create instance of a user

      user = new User({
        name,
        email,
        avatar,
        password
      });

      // Encrypt password

      const salt = await bcrypt.genSalt(10);
      // store the password in a hash by bcrypt
      user.password = await bcrypt.hash(password, salt);
      // save the user to the database
      await user.save();
      //Return jsonwebtoken

      //create payload

      const payload = {
        user: {
          id: user.id
        }
      };
      // refer to the documentation https://github.com/auth0/node-jsonwebtoken
      jwt.sign(
        payload,
        //get token from config where we set the jwttoken
        config.get("jwtSecret"),
        { expiresIn: 360000 },
        (err, token) => {
          if (err) throw err;
          //if no err, then send the token back to the client
          res.json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send("Server Error");
    }
  }
);

module.exports = router;
