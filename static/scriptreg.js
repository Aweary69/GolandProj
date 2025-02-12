/*
document.querySelector("#register-form").addEventListener("submit", async function(event) {
    event.preventDefault();

    const name = document.querySelector("input[name='name']").value.trim();
    const email = document.querySelector("input[name='email']").value.trim();
    const password = document.querySelector("input[name='password']").value.trim();

    if (!name || !email || !password) {
        alert("Все поля обязательны!");
        return;
    }

    const data = { name, email, password };

    try {
        const response = await fetch("http://localhost:8000/register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(data)
        });

        const result = await response.json();

        if (response.ok) {
            alert(result.message);
            window.location.href = "login.html";
        } else {
            alert(result.error || "Ошибка регистрации");
        }
    } catch (error) {
        console.error("Ошибка:", error);
        alert("Ошибка сети. Попробуйте снова.");
    }
});*/
