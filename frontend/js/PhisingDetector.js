async function detectPhishing() {
    const input = document.getElementById("phishingInput").value.trim();
    const resultDiv = document.getElementById("result");

    if (!input) {
        resultDiv.innerHTML = "<p style='color:red;'>Please enter a message or URL.</p>";
        return;
    }

    try {
        fetch("https://suraksha-ai-oue7.onrender.com/analyze", {

            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: input })
        });

        if (!response.ok) throw new Error("Backend error");

        const data = await response.json();

        resultDiv.innerHTML = `
            <h3>Analysis Result:</h3>
            <p><strong>Risk:</strong> ${data.risk}</p>
            <p><strong>Confidence:</strong> ${data.confidence}%</p>
            <p><strong>Reasons:</strong> ${data.reasons.join(", ")}</p>
            <p><strong>AI Explanation:</strong> ${data.ai_explanation}</p>
        `;
    } catch (err) {
        resultDiv.innerHTML = `<p style="color:red;">Error: ${err.message}</p>`;
    }
}
