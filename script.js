document.getElementById("authForm").addEventListener("submit", async function(event) {
    event.preventDefault();
    
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const action = document.getElementById("action").value;

    let url;
    if (action === "signup") {
        url = "/signup";
    } else {
        url = "/signin";
    }

    try {
        const response = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ username: username, password: password })
        });

        if (!response.ok) {
            const data = await response.json();
            if (data.error) {
                alert(data.error);
            } else {
                alert("Failed to authenticate");
            }
        } else {
            const data = await response.json();
            if (data.token) {
                localStorage.setItem("token", data.token);
                alert("Successfully authenticated!");
                // Redirect or perform further actions after successful authentication
            } else if (data.message) {
                alert(data.message);
            }
        }
    } catch (error) {
        console.error("Error:", error);
        alert("Failed to authenticate");
    }
});
