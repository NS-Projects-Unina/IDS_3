document.addEventListener("DOMContentLoaded", () => {
    const tableBody = document.getElementById("logTable");
  
    fetch("/history")
      .then(response => response.json())
      .then(data => {
        tableBody.innerHTML = ""; // Rimuove il messaggio di "Caricamento dati..."
        data.forEach(log => {
          const row = document.createElement("tr");
          // Formatta il timestamp in una stringa locale leggibile
          const timestamp = new Date(log.timestamp).toLocaleString();
          row.innerHTML = `
            <td>${timestamp}</td>
            <td>${log.alertLevel}</td>
            <td>${log.attackType}</td>
            <td>${log.source}</td>
          `;
          tableBody.appendChild(row);
        });
      })
      .catch(error => {
        console.error("Errore nel recupero dei log:", error);
        tableBody.innerHTML = `<tr><td colspan="4" class="text-center">Errore nel recupero dei dati</td></tr>`;
      });
  });
  