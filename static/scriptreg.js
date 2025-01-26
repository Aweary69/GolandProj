document.getElementById('registerForm').addEventListener('submit', async function(event) {
    event.preventDefault();
    const form = event.target;

    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());

    const response = await fetch(form.action, {
        method: form.method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });

    const result = await response.json();
    if (response.ok && result.redirect) {
        window.location.href = result.redirect;
    } else {
        alert(result.message || 'An error occurred');
    }
});