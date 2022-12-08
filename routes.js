import { Router } from "express";
import sql from "./config/db.js";
import logger from "./config/logger.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { JWT_SECRET } from "./config/envs.js";

const router = Router();

router.post("/signup", (req, res) => {
    logger.info("POST /signup");
    const { fullname, password, username, gender, phone } = req.body;
    console.table(req.body);
    // check is username already exists
    sql.query(
        `SELECT * FROM users WHERE username = ?`,
        [username],
        (err, result) => {
            if (err) {
                res.status(500).json({ error: err });
            } else if (result.length > 0) {
                res.status(200).render("signup", {
                    error: username + " is already taken as username",
                });
            } else {
                const saltRounds = 10;
                const encryptedPassword = bcrypt.hashSync(password, saltRounds);
                // insert into database
                sql.query(
                    `INSERT INTO users (fullname, password , username, gender, phone) VALUES (?, ?, ?, ?, ?)`,
                    [fullname, encryptedPassword, username, gender, phone],
                    (err, result) => {
                        if (err) {
                            res.status(500).json({ error: err });
                        } else {
                            res.status(201).redirect("/login");
                        }
                    }
                );
            }
        }
    );
});

router.post("/login", (req, res) => {
    logger.info("POST /login");
    const { username, password } = req.body;
    sql.query(
        `SELECT * FROM users WHERE username = ?`,
        [username],
        (err, result) => {
            if (err) {
                res.status(500).json({ error: err });
            } else if (result.length > 0) {
                const user = result[0];
                const isPasswordCorrect = bcrypt.compareSync(
                    password,
                    user.password
                );
                if (isPasswordCorrect) {
                    const token = jwt.sign(
                        {
                            id: user.id,
                            username: user.username,
                        },
                        JWT_SECRET,
                        {
                            expiresIn: "2m",
                        }
                    );

                    logger.info("✅ Login successful");
                    res.cookie("token", token, {
                        httpOnly: true,
                    })
                        .status(200)
                        .render("profile", { user });
                } else {
                    res.status(200).render("login", {
                        error: "Invalid credentials",
                    });
                }
            } else {
                res.status(200).render("login", {
                    error: "Username does not exist",
                });
            }
        }
    );
});

router.post("/updateprofile", (req, res) => {
    try {
        logger.info("POST /editprofile");
        const token = req.header("Cookie")?.split("=")[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const { fullname, username, gender, phone } = req.body;
        // check if username already exists
        sql.query(
            `SELECT * FROM users WHERE username = ?`,
            [username],
            (err, result) => {
                if (err) {
                    res.status(500).json({ error: err });
                } else if (result.length > 0) {
                    res.status(200).render("editprofile", {
                        error: username + " is already taken as username",
                    });
                } else {
                    sql.query(
                        `UPDATE users SET fullname = ?, username
        = ?, gender = ?, phone = ? WHERE id = ?`,
                        [fullname, username, gender, phone, decoded.id],
                        (err, result) => {
                            if (err) {
                                res.status(500).json({ error: err });
                            } else {
                                res.redirect("/profile");
                            }
                        }
                    );
                }
            }
        );
    } catch (error) {
        logger.error(error);
        res.redirect("/login");
    }
});

router.post("/updatepassword", (req, res) => {
    try {
        logger.info("POST /updatepassword");
        const token = req.header("Cookie")?.split("=")[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const { oldpassword, newpassword, confirmpassword } = req.body;
        if (newpassword !== confirmpassword) {
            res.status(200).render("editpassword", {
                error: "New password and confirm password do not match",
            });
            return;
        }
        sql.query(
            `SELECT * FROM users WHERE id = ?`,
            [decoded.id],
            (err, result) => {
                if (err) {
                    res.status(500).json({ error: err });
                } else if (result.length > 0) {
                    const user = result[0];
                    const isPasswordCorrect = bcrypt.compareSync(
                        oldpassword,
                        user.password
                    );
                    if (isPasswordCorrect) {
                        const saltRounds = 10;
                        const encryptedPassword = bcrypt.hashSync(
                            newpassword,
                            saltRounds
                        );
                        sql.query(
                            `UPDATE users SET password = ? WHERE id = ?`,
                            [encryptedPassword, decoded.id],
                            (err, result) => {
                                if (err) {
                                    res.status(500).json({ error: err });
                                } else {
                                    res.redirect("/profile");
                                }
                            }
                        );
                    } else {
                        res.status(200).render("editpassword", {
                            error: "Wrong Old Password",
                        });
                    }
                } else {
                    res.status(200).render("editprofile", {
                        error: "Username does not exist",
                    });
                }
            }
        );
    } catch (error) {
        logger.error(error);
        res.redirect("/login");
    }
});

export default router;
