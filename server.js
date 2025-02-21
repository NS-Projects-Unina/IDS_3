//codice del server per esposizione dell'interfaccia, da aggiungere almeno https
//prova
const express = require("express");
const { exec } = require("child_process");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.static(path.join(__dirname, "interfaccia/")));


app.listen(PORT, () => {
    console.log(`Server in ascolto su http://localhost:${PORT}`);
});

app.get("/logs", (req, res) => {
   
    const command = 'python analyze.py "C:/Users/fabri/Desktop/Cose Importanti/Università/Magistrale/Network Security/progetto/raccolta.csv"';
    
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
            res.json(logs);
        } catch (parseError) {
            console.error("Errore nel parsing dei dati JSON:", parseError);
            console.error("Output ricevuto:", stdout);
            res.status(500).json({ error: "Errore nel parsing dei dati di analisi" });
        }
    });
});



