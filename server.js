//codice del server per esposizione dell'interfaccia, da aggiungere almeno https
//prova
const express = require("express");
const { exec } = require("child_process");
const cors = require("cors");
const path = require("path");
const https = require("https");
const fs = require("fs");
const mongoose = require("mongoose");

const app = express();
const PORT = 3000;
const PORT_HTTPS = 8080;

const key = fs.readFileSync("server.key");
const cert = fs.readFileSync("server.cert");

const MONGO_URI = "mongodb://127.0.0.1:27017/network_logs"; 
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("MongoDB connesso"))
    .catch(err => console.error("Errore connessione MongoDB:", err));

// Definizione schema e modello per il db
const logSchema = new mongoose.Schema({
    timestamp: { type: Date, default: Date.now },
    alertLevel: String,
    attackType: String,
    source: String
});
const Log = mongoose.model("Log", logSchema);


app.use(cors());
app.use(express.static(path.join(__dirname, "interfaccia/")));


app.listen(PORT, () => {
    console.log(`Server in ascolto su http://localhost:${PORT}`);
});

https.createServer({ key, cert }, app).listen(PORT_HTTPS, () => {
    console.log(`Server HTTPS in ascolto su https://localhost:${PORT_HTTPS}`);
});

app.get("/logs", (req, res) => {
   
    const command = 'python analyze.py "raccolta.csv"';
    
    exec(command, (error, stdout, stderr) => {
        if (error) {
            console.error(`Errore nell'esecuzione dello script: ${error.message}`);
            return res.status(500).json({ error: "Errore nell'analisi dei pacchetti" });
        }
        if (stderr) {
            console.error(`Errore nello script: ${stderr}`);
            return res.status(500).json({ error: "Errore nello script di analisi" });
        }

        try {
            const logs = JSON.parse(stdout);
            logs.forEach(logData => {
                const log = new Log({
                    timestamp: logData.timestamp,
                    alertLevel: logData.alert_level,
                    attackType: logData.threat_type,
                    source: logData.source
                });
    
                log.save()
                    .then(() => {
                        console.log("Log salvato su MongoDB");
                    })
                    .catch((err) => {
                        console.error("Errore durante il salvataggio del log:", err);
                    });
            });
            res.json(logs);
        } catch (parseError) {
            console.error("Errore nel parsing dei dati JSON:", parseError);
            res.status(500).json({ error: "Errore nel parsing dei dati di analisi" });
        }
    });
});
app.get("/history", (req, res) => {
    Log.find({})
        .then(logs => res.json(logs))
        .catch(err => {
            console.error("Errore nel recupero dei log:", err);
            res.status(500).json({ error: "Errore nel recupero dei log" });
        });
});


