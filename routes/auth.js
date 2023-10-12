const express = require("express")
const router = express.Router()
const registerContoller = require("../controllers/authController")

router.post("/", registerContoller.handleLogin)

module.exports = router
