async function fetchLogs() {
    try {
        const response = await fetch("/logs");
        const logs = await response.json();
        const tableBody = document.getElementById("logTable");
        tableBody.innerHTML = "";

        logs.forEach(log => {
            const row = `<tr>
                <td>${new Date(log.timestamp).toLocaleString()}</td>
                <td class="${log.alert_level === 'High' ? 'text-danger' : log.alert_level === 'Medium' ? 'text-warning' : 'text-success'}">
                    ${log.alert_level}
                </td>
                <td>${log.threat_type}</td>
                <td>${log.source}</td>
            </tr>`;
            tableBody.innerHTML += row;
        });
    } catch (error) {
        console.error("Errore nel recupero dei dati:", error);
    }
}

// Aggiorna la tabella ogni 10 secondi
setInterval(fetchLogs, 10000);
fetchLogs();
