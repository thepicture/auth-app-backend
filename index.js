// @ts-nocheck
require("dotenv").config();

const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const bodyParser = require("body-parser");

const DEFAULT_PORT = 3002;
const PORT = process.env.PORT || DEFAULT_PORT;

const ACCESS_TOKEN_PRIVATE_KEY = process.env.ACCESS_TOKEN_PRIVATE_KEY;
const REFRESH_TOKEN_PRIVATE_KEY = process.env.REFRESH_TOKEN_PRIVATE_KEY;
const SECOND_IN_MILLISECONDS = 1000;

const { default: jwtDecode } = require("jwt-decode");

const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database("./products.db", (err) => {
  if (err) {
    console.log("Failed to open or create database: " + err);
  } else {
    console.log("Database has been opened or created");
  }
});

const app = express();
app.use(cookieParser());
app.use(
  cors({
    origin: process.env.ORIGIN,
    optionsSuccessStatus: 200, // IE11 fix
    credentials: true,
  })
);

if (process.env.NODE_ENV === "production") {
  console.log("Production enabled");
  app.use(express.static("build"));
}

app.use(bodyParser.json());

app.listen(PORT, () => {
  console.log("Listening on port " + PORT + "...");
});

app.post("/api/signin", (req, res) => {
  const { login, password } = req.body;
  db.get(
    `select user.id, role.title
            from user
            inner join role
            on user.roleId=role.id
            where login = ? and password = ?
            limit 1`,
    [login, password],
    (err, row) => {
      if (err) {
        res.sendStatus(500);
      } else {
        if (!row) {
          res.sendStatus(401);
        } else {
          const accessToken = jwt.sign(
            { role: row.role },
            ACCESS_TOKEN_PRIVATE_KEY,
            { subject: String(row.id), expiresIn: "8s" }
          );
          const refreshToken = jwt.sign(
            { role: row.role },
            REFRESH_TOKEN_PRIVATE_KEY,
            { subject: String(row.id), expiresIn: "16s" }
          );
          res.cookie("accessToken", "Bearer " + accessToken, {
            httpOnly: true,
            maxAge: SECOND_IN_MILLISECONDS * 8,
          });
          res.cookie("refreshToken", "Bearer " + refreshToken, {
            httpOnly: true,
            maxAge: SECOND_IN_MILLISECONDS * 16,
          });
          res.sendStatus(200);
        }
      }
    }
  );
});

const USER_ROLE_ID = 2;
app.post("/api/signup", (req, res) => {
  const { login, password, fullName } = req.body;

  db.get(
    `select user.id
            from user
            where login = ?
            limit 1`,
    login,
    (err, row) => {
      if (err) {
        res.sendStatus(500);
      } else {
        if (row) {
          res.sendStatus(409);
        } else {
          db.run(
            `insert into user (login, password, fullName, roleId)
                        values (?,?,?,?)`,
            [login, password, fullName, USER_ROLE_ID]
          );
          res.sendStatus(201);
        }
      }
    }
  );
});

app.get("/api/getAccessToken", (req, res) => {
  if (!req.cookies.refreshToken) return res.sendStatus(403);
  else {
    const refreshToken = req.cookies.refreshToken.split(" ")[1];
    jwt.verify(refreshToken, REFRESH_TOKEN_PRIVATE_KEY, (err) => {
      if (err) return res.sendStatus(403);
      else
        db.get(
          `select user.id, role.title
                        from user
                        inner join role
                        on user.roleId=role.id
                        where user.id = ?
                        limit 1`,
          [jwtDecode(refreshToken).sub],
          (err, row) => {
            if (err) {
              res.sendStatus(500);
            } else {
              if (!row) {
                res.sendStatus(401);
              } else {
                const accessToken = jwt.sign(
                  { role: row.role },
                  ACCESS_TOKEN_PRIVATE_KEY,
                  { subject: String(row.id), expiresIn: "8s" }
                );
                res.cookie("accessToken", "Bearer " + accessToken, {
                  httpOnly: true,
                  maxAge: SECOND_IN_MILLISECONDS * 8,
                });
                res.sendStatus(200);
              }
            }
          }
        );
    });
  }
});

const verifyAccessToken = () => (req, res, next) => {
  if (!req.cookies.accessToken) return res.sendStatus(401);
  const accessToken = req.cookies.accessToken.split(" ")[1];
  jwt.verify(accessToken, ACCESS_TOKEN_PRIVATE_KEY, (err) => {
    if (err) res.sendStatus(500);
    else if (jwtDecode(accessToken).exp * SECOND_IN_MILLISECONDS > +new Date())
      next();
    else res.sendStatus(401);
  });
};

app.use(verifyAccessToken());

app.get("/api/verifyAccessToken", (_req, res) => {
  res.sendStatus(200);
});

app.get("/api/me", (req, res) => {
  const accessToken = req.cookies.accessToken.split(" ")[1];
  db.get(
    `select user.id as userId, fullName, role.title as roleTitle
            from user
            inner join role
            on user.roleId=role.id
            where user.id = ?
            limit 1`,
    [jwtDecode(accessToken).sub],
    (err, row) => {
      if (err) {
        res.sendStatus(500);
      } else {
        if (!row) {
          res.sendStatus(401);
        } else {
          res.send({
            user: {
              id: row.userId,
              fullName: row.fullName,
              roleTitle: row.roleTitle,
            },
          });
        }
      }
    }
  );
});

app.get("/api/products", (_req, res) => {
  try {
    db.all(`select * from product`, (err, rows) => {
      if (err) {
        res.sendStatus(500);
      } else {
        if (rows) {
          res.send(rows);
        } else {
          res.sendStatus(500);
        }
      }
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

app.post("/api/order", (req, res) => {
  const accessToken = req.cookies.accessToken.split(" ")[1];
  try {
    db.run(
      `insert into [order] (creationUnixTime, userId)
                       values (?,?)`,
      [+new Date(), jwtDecode(accessToken).sub],
      function (err) {
        if (!err) {
          const productIds = req.body;
          for (let productId of productIds) {
            db.run(
              `insert into productOfOrder (productId, orderId)
                                   values (?,?)`,
              [productId, this.lastID],
              (err) => {
                if (err) {
                  console.log(err);
                  res.sendStatus(500);
                  return;
                }
              }
            );
          }
        } else {
          console.log(err);
          res.sendStatus(500);
          return;
        }
      }
    );
    res.sendStatus(201);
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

app.get("/api/order", (req, res) => {
  const accessToken = req.cookies.accessToken.split(" ")[1];
  try {
    db.all(
      `select [order].id as orderId, 
                       [order].creationUnixTime, 
                       SUM(product.priceInCents) as sumInCents,
                       COUNT(product.id) as countOfProducts from [order]
                inner join productOfOrder
                on [order].id = productOfOrder.orderId
                inner join product
                on productOfOrder.productId = product.id
                where userId=?
                group by [order].id`,
      [jwtDecode(accessToken).sub],
      (err, rows) => {
        if (err) {
          res.sendStatus(500);
        } else {
          if (rows) {
            res.send(rows);
          } else {
            res.sendStatus(500);
          }
        }
      }
    );
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

app.get("/api/orderProducts/:id", (req, res) => {
  const accessToken = req.cookies.accessToken.split(" ")[1];
  try {
    db.all(
      `select product.id, 
                       product.title,
                       product.priceInCents,
                       product.imageUrl,
                       product.alt
                from productOfOrder
                inner join product on productOfOrder.productId = product.id
                inner join [order] on productOfOrder.orderId = [order].id
                where [order].userId = ? and productOfOrder.orderId = ?`,
      [jwtDecode(accessToken).sub, req.params.id],
      (err, rows) => {
        if (err) {
          console.log(err);
          res.sendStatus(500);
        } else {
          if (rows) {
            res.send(rows);
          } else {
            res.sendStatus(404);
          }
        }
      }
    );
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});
