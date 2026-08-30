import "dotenv/config";
import express from "express";
import OpenAI from "openai";

const app = express();
const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

app.use(express.json());
app.use(express.static("public"));

app.post("/api/chat", async (req, res) => {
  try {
    const message = String(req.body?.message || "").trim();
    if (!message) return res.status(400).json({ error: "Message is required." });

    const response = await client.responses.create({
      model: "gpt-5.6-luna",
      input: message
    });

    res.json({ reply: response.output_text });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "AI request failed. Check your API key and server." });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Raiyan AI running on http://localhost:${PORT}`));
