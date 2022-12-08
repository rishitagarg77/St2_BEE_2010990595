import express from "express";
import ejs from "ejs";
import path from "path";
import sql, { connectDb } from "./config/db.js";
import logger from "./config/logger.js";
import router from "./routes.js";
import jwt from "jsonwebtoken";
import { JWT_SECRET } from "./config/envs.js";

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const __dirname = path.resolve();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
    res.render("index");
});

// this function will redirect the user to profile page if he is logged in
const redirectIfLoggedIn = (req, res, next) => {
    const token = req.header("Cookie")?.split("=")[1];
    if (token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            if (decoded) {
                // check if expired
                const currentTime = Date.now() / 1000;
                if (decoded.exp > currentTime) {
                    return res.redirect("/profile");
                }
                // find user
                sql.query(
                    `SELECT * FROM users WHERE id = ?`,
                    [decoded.id],
                    (err, result) => {
                        if (err) {
                            res.status(500).json({ error: err });
                        } else if (result.length > 0) {
                            res.status(200).render("profile", {
                                user: result[0],
                            });
                            return;
                        } else {
                            res.redirect("/login");
                        }
                    }
                );
            }
        } catch (error) {
            next();
        }
    } else {
        next();
    }
};

app.get("/signup", redirectIfLoggedIn, (req, res) => {
    res.render("signup", {
        error: "",
    });
});
app.get("/login", redirectIfLoggedIn, (req, res) => {
    res.render("login", {
        error: "",
    });
});
app.get("/logout", (req, res) => {
    res.setHeader("Set-Cookie", "token=;").redirect("/login");
});
app.get("/profile", (req, res) => {
    try {
        const token = req.header("Cookie")?.split("=")[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        console.log(decoded);
        sql.query(
            `SELECT * FROM users WHERE id = ?`,
            [decoded.id],
            (err, result) => {
                if (err) {
                    res.status(500).json({ error: err });
                } else if (result.length > 0) {
                    res.status(200).render("profile", {
                        user: result[0],
                    });
                } else {
                    res.redirect("/login");
                }
            }
        );
    } catch (error) {
        console.log(error);
        res.setHeader("Set-Cookie", "token=;");
        res.redirect("/login");
    }
});
app.get("/editprofile", (req, res) => {
    try {
        const token = req.header("Cookie")?.split("=")[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        sql.query(
            `SELECT * FROM users WHERE id = ?`,
            [decoded.id],
            (err, result) => {
                if (err) {
                    res.status(500).json({ error: err });
                } else if (result.length > 0) {
                    res.status(200).render("editprofile", {
                        user: { ...result[0], password: null },
                        error: "",
                    });
                } else {
                    res.redirect("/login");
                }
            }
        );
    } catch (error) {
        console.log(error);
        res.setHeader("Set-Cookie", "token=;");
        res.redirect("/login");
    }
});
app.get("/editpassword", (req, res) => {
    try {
        const token = req.header("Cookie")?.split("=")[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        sql.query(
            `SELECT * FROM users WHERE id = ?`,
            [decoded.id],
            (err, result) => {
                if (err) {
                    res.status(500).json({ error: err });
                } else if (result.length > 0) {
                    res.status(200).render("editpassword", {
                        user: { ...result[0], password: null },
                        error: "",
                    });
                } else {
                    res.redirect("/login");
                }
            }
        );
    } catch (error) {
        console.log(error);
        res.setHeader("Set-Cookie", "token=;");
        res.redirect("/login");
    }
});

app.get("/admin", (req, res) => {
    sql.query(`SELECT * FROM users`, (err, result) => {
        if (err) {
            res.status(500).json({ error: err });
        } else if (result.length > 0) {
            res.status(200).render("admin", {
                users: result,
            });
        } else {
            res.redirect("/login");
        }
    });
});

app.get("/delete/:id", (req, res) => {
    const id = req.params.id;
    sql.query(`DELETE FROM users WHERE id = ?`, [id], (err, result) => {
        if (err) {
            res.status(500).json({ error: err });
        } else {
            res.redirect("/admin");
        }
    });
});

app.use(router);

connectDb().then(() => {
    logger.info("\n\n--------------------");
    logger.success("✅ Connected to database");
    app.listen(3000, () => {
        logger.info("✅ Server started on port 3000");
        logger.info("✨ Open http://localhost:3000");
    });
});
