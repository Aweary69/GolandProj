document.getElementById('loginForm').addEventListener('submit', async (event) => {
    event.preventDefault(); // Prevent the default form submission

    const formData = new FormData(event.target);
    const email = formData.get('email');
    const password = formData.get('password');

    try {
        const response = await fetch('/api/users/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
        });

        const data = await response.json();
        if (response.ok) {
            window.location.href = data.redirect || "/home.html";
        } else {
            alert(data.error || "Login failed");
        }

    } catch (error) {
        console.error('Error during login:', error);
        alert('An error occurred. Please try again.');
    }
});