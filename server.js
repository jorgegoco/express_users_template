const express = require("express")
const app = express()
const cors = require("cors")
const { logger } = require("./middleware/logEvents")
const errorHandler = require("./middleware/errorHandler")
const PORT = process.env.PORT || 3500

// custom middleware logger
app.use(logger)

// Cross Origin Resource Sharing
app.use(cors())
app.use(errorHandler)

app.listen(PORT, () => console.log(`Server running on port ${PORT}`))
