document.getElementById("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const fileInput = document.getElementById("pem-file");
    const file = fileInput.files[0];

    if (!file) {
        alert("Załaduj plik PEM!");
        return;
    }

    const pemText = await file.text();
    
    // Przygotowanie danych JSON
    const jsonData = {
        username: username,
        password: password,
        public_key: pemText
    };

    const response = await fetch("/api/login", {
        method: "POST",
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(jsonData)
    });

    const result = await response.json();

    if (response.ok) {
        window.location.href = "/chat";
    } else {
        alert(result.error || "Błąd logowania");
    }
});