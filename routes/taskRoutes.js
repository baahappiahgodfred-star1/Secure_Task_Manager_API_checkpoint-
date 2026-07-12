const express = require("express");

const router = express.Router();

const verifyToken = require("../middleware/authMiddleware");

const {
  createTask,
  getTasks,
  deleteTask,
} = require("../controllers/taskController");

router.post("/", verifyToken, createTask);

router.get("/", verifyToken, getTasks);

router.delete("/:id", verifyToken, deleteTask);

module.exports = router;