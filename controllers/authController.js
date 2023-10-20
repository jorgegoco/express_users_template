const User = require("../model/User")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")

const handleLogin = async (req, res) => {
  const cookies = req.cookies.jwt
  console.log(`cookie available at login: ${JSON.stringify(cookies)}`)
  const { user, pwd } = req.body
  if (!user || !pwd)
    return res
      .status(400)
      .json({ message: "Username and password are required" })
  const foundUser = await User.findOne({ username: user }).exec()
  if (!foundUser) return res.sendStatus(401) //Unauthorized
  // evaluate password
  const match = await bcrypt.compare(pwd, foundUser.password)
  if (match) {
    const roles = Object.values(foundUser.roles).filter(Boolean)
    // create JWTs
    const accessToken = jwt.sign(
      { UserInfo: { username: foundUser.username, roles: roles } },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "15m" }
    )
    const newRefreshToken = jwt.sign(
      { username: foundUser.username },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: "1d" }
    )

    let newRefreshTokenArray = !cookies
      ? foundUser.refreshToken
      : foundUser.refreshToken.filter((rt) => rt !== cookies)

    if (cookies) {
      /* 
            Scenario added here: 
                1) User logs in but never uses RT and does not logout 
                2) RT is stolen
                3) If 1 & 2, reuse detection is needed to clear all RTs when user logs in
            */
      const refreshToken = cookies.jwt
      const foundToken = await User.findOne({ refreshToken }).exec()

      // Detected refresh token reuse!
      if (!foundToken) {
        console.log("attempted refresh token reuse at login!")
        // clear out ALL previous refresh tokens
        newRefreshTokenArray = []
      }

      res.clearCookie("jwt", { httpOnly: true, sameSite: "None" }) // add secure: true in https connections
    }

    // Saving refreshToken with current user
    foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken]
    const result = await foundUser.save()
    console.log(result)

    res.cookie("jwt", newRefreshToken, {
      httpOnly: true, // This avoids any foreign javascript code to have access to that cookie
      sameSite: "Lax",
      // secure: true, // when working in dev mode, like thunderclient, this must be deleted to accept cookies with http
      maxAge: 24 * 60 * 60 * 1000,
    })
    res.json({ roles, accessToken })
  } else {
    res.sendStatus(401)
  }
}

module.exports = { handleLogin }
