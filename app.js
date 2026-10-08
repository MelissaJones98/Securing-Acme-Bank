process.loadEnvFile(); // loads variable from .env into process.env
const sqlite3 = require("sqlite3");
const express = require("express");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const helmet = require("helmet");
const { body, query, validationResult } = require("express-validator");

const db = new sqlite3.Database("./bank_sample.db");

const app = express();
const PORT = 3000;
app.set("view engine", "ejs");

// XSS FIX: security headers + Content Security Policy
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        "script-src": ["'self'", "https://cdn.jsdelivr.net"],
        "style-src": ["'self'", "https://cdn.jsdelivr.net", "'unsafe-inline'"],
        // We serve over plain http on localhost during development
        "upgrade-insecure-requests": null,
      },
    },
  })
);

app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: process.env.SESSION_SECRET, // kept in .env (git-ignored) so it's never committed
    resave: true,
    saveUninitialized: true,
    rolling: true, // Reset the expiry on every request, so maxAge works as an idle timeout instead of a fixed time from login
    cookie: {
       httpOnly: true, // stops JavaScript (document.cookie) from reading the cookie so an XSS payload can't steal the session
       secure: process.env.NODE_ENV === "production",
       // only send cookie over HTTPS, so it can't be secretly read on the network
       // only true in production: on http://localhost a Secure cookie
       // is never sent and login silently breaks
       sameSite: "strict", // never sends the cookie on requests that start from another site - CSRF defence (stops most CSRF attacks) 
       maxAge: 15 * 60 * 1000, // log out after 15mins of inactivity (value in milliseconds)
    },
  })
);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// VALIDATION: rules for each form's input (express-validator)
const loginValidation = [
  body("username").trim().notEmpty().isLength({ max: 50 }),
  // Not trimmed or escaped: that would change the password the user typed
  body("password").notEmpty().isLength({ max: 100 }),
];

const transferValidation = [
  body("account_to")                                        // 1. look at the account_to field
    .trim()                                                 // 2. remove spaces: " 123 " -> "123"
    .isInt({ min: 1 })                                      // 3. must be a whole number of 1 or more
    .withMessage("Account number must be a valid number")   // 3a. error text if step 3 fails
    .toInt(),                                               // 4. convert the text "123" into the number 123

  body("amount")                                            // 1. look at the amount field
    .trim()                                                 // 2. remove spaces: " 123 " -> "123"
    .isInt({ min: 1, max: 10000 })                          // 3. must be a whole number between 1 and 10,000
    .withMessage("Amount must be between £1 and £10,000")   // 3a. error text if step 3 fails
    .toInt(),                                               // 4. convert the text "123" into the number 123  
];

const forumValidation = [
  // Stored exactly as typed (no escape()): forum.ejs HTML-encodes it on output,
  // and the INSERT uses a parameter so quotes can't break the SQL
  body("comment")
    .trim()
    .notEmpty()
    .withMessage("Comment cannot be empty")
    .isLength({ max: 500 })
    .withMessage("Comment must be 500 characters or fewer")
];

const ledgerValidation = [
  // id is optional (no id = show all), but if given it must be a whole account number
  query("id").optional({ checkFalsy: true }).isInt({ min: 1 }).toInt(),
];

app.get("/", function (request, response) {
  response.sendFile(path.join(__dirname + "/html/login.html"));
});

//LOGIN SQL
app.post("/auth", loginValidation, function (request, response) {
  var username = request.body.username;
  var password = request.body.password;
  if (validationResult(request).isEmpty()) {
    db.get(
      `SELECT * FROM users WHERE username = '${request.body.username}' AND password = '${request.body.password}'`,
      function (error, results) {
        console.log(error);
        console.log(results);
        if (results) {
          request.session.loggedin = true;
          request.session.username = results["username"];
          request.session.balance = results["balance"];
          request.session.file_history = results["file_history"];
          request.session.account_no = results["account_no"];
          response.redirect("/home");
        } else {
          response.send("Incorrect Username and/or Password!");
        }
        response.end();
      }
    );
  } else {
    response.send("Please enter Username and Password!");
    response.end();
  }
});

//Home Menu No Exploits Here.
app.get("/home", function (request, response) {
  if (request.session.loggedin) {
    username = request.session.username;
    balance = request.session.balance;
    response.render("home_page", { username, balance });
  } else {
    response.redirect("/");
  }
  response.end();
});

//CSRF CODE SECURED. SEE HEADERS SET ABOVE
app.get("/transfer", function (request, response) {
  if (request.session.loggedin) {
    var sent = "";
    response.render("transfer", { sent });
  } else {
    response.redirect("/");
  }
});

//CSRF CODE
app.post("/transfer", transferValidation, function (request, response) {
  if (request.session.loggedin) {
    const errors = validationResult(request);
    if (!errors.isEmpty()) {
      // Show the first rule that failed, e.g. "Amount must be a positive whole number"
      return response.render("transfer", { sent: errors.array()[0].msg });
    }
    console.log("Transfer in progress");
    var balance = request.session.balance;
    // Already converted to numbers by the validation chain
    var account_to = request.body.account_to;
    var amount = request.body.amount;
    var account_from = request.session.account_no;
    if (account_to && amount) {
      if (balance > amount) {
        db.get(
          `UPDATE users SET balance = balance + ${amount} WHERE account_no = ${account_to}`,
          function (error, results) {
            console.log(error);
            console.log(results);
          }
        );
        db.get(
          `UPDATE users SET balance = balance - ${amount} WHERE account_no = ${account_from}`,
          function (error, results) {
            var sent = "Money Transfered";
            response.render("transfer", { sent });
          }
        );
      } else {
        var sent = "You Don't Have Enough Funds.";
        response.render("transfer", { sent });
      }
    } else {
      var sent = "";
      response.render("transfer", { sent });
    }
  } else {
    response.redirect("/");
  }
});

//PATH TRAVERSAL CODE
app.get("/download", function (request, response) {
  if (request.session.loggedin) {
    file_name = request.session.file_history;
    response.render("download", { file_name });
  } else {
    response.redirect("/");
  }
  response.end();
});

app.post("/download", function (request, response) {
  if (request.session.loggedin) {
    var file_name = request.body.file;

    response.statusCode = 200;
    response.setHeader("Content-Type", "text/html");

    // Change the filePath to current working directory using the "path" method
    const filePath = "history_files/" + file_name;
    console.log(filePath);
    try {
      content = fs.readFileSync(filePath, "utf8");
      response.end(content);
    } catch (err) {
      console.log(err);
      response.end("File not found");
    }
  } else {
    response.redirect("/");
  }
  response.end();
});

//XSS CODE
app.get("/public_forum", function (request, response) {
  if (request.session.loggedin) {
    db.all(`SELECT username,message FROM public_forum`, (err, rows) => {
      console.log(rows);
      console.log(err);
      response.render("forum", { rows });
    });
  } else {
    response.redirect("/");
  }
  //response.end();
});

app.post("/public_forum", forumValidation, function (request, response) {
  if (request.session.loggedin) {
    var comment = request.body.comment;
    var username = request.session.username;
    if (validationResult(request).isEmpty()) {
      db.all(
        `INSERT INTO public_forum (username,message) VALUES ('${username}','${comment}')`,
        (err, rows) => {
          console.log(err);
        }
      );
      db.all(`SELECT username,message FROM public_forum`, (err, rows) => {
        console.log(rows);
        console.log(err);
        response.render("forum", { rows });
      });
    } else {
      db.all(`SELECT username,message FROM public_forum`, (err, rows) => {
        console.log(rows);
        console.log(err);
        response.render("forum", { rows });
      });
    }
    comment = "";
  } else {
    response.redirect("/");
  }
  comment = "";
  //response.end();
});

//SQL UNION INJECTION
app.get("/public_ledger", ledgerValidation, function (request, response) {
  if (request.session.loggedin) {
    if (!validationResult(request).isEmpty()) {
      // Invalid id (e.g. "1' UNION SELECT ..."): show an empty result instead of querying
      return response.render("ledger", { rows: [] });
    }
    var id = request.query.id;
    if (id) {
      db.all(
        `SELECT * FROM public_ledger WHERE from_account = '${id}'`,
        (err, rows) => {
          console.log("PROCESSING INPU");
          console.log(err);
          if (rows) {
            response.render("ledger", { rows });
          } else {
            response.render("ledger", { rows });
          }
        }
      );
    } else {
      db.all(`SELECT * FROM public_ledger`, (err, rows) => {
        if (rows) {
          response.render("ledger", { rows });
        } else {
          response.render("ledger", { rows });
        }
      });
    }
  } else {
    response.redirect("/");
  }
  //response.end();
});

app.listen(PORT, () => {
  console.log(`Server is running on port: ${PORT}`);
});
