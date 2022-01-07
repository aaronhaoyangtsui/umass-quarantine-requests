function setup() {
    document.getElementById("loginButton").addEventListener("click", login);
    document.getElementById("createAccountButton").addEventListener("click", createAccount);
}
async function login(event) {
    event.preventDefault();
    const email = document.getElementById("userEmail").value;
    const password = document.getElementById("userPassword").value;
    const data = {"user_email":email, "password":password};
    fetch("/user/login",{
        method: "POST",
        cache: "no-cache",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data),
        redirect: 'follow'
    }).then((response) => {
        if (response.status >= 400) {
            return {"login_status" : "invalid"};
        }
        return response.json();
    }).then((data) => {
        if (data["login_status"] === "valid") {
            window.localStorage.setItem('user_email', email); //used to set default email on page for making requests
            window.location.href = "./welcome.html";
        } else {
            alert("Invalid login credentials.");
        }
    });
}
async function createAccount(event) {
    event.preventDefault();
    const email = document.getElementById("userEmail").value;
    const password = document.getElementById("userPassword").value;
    const data = {"user_email":email, "password":password};
    fetch("/user/new",{
        method: "POST",
        cache: "no-cache",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    }).then((response) => {
        return response.status;
    }).then((status) => {
        if (status === 201) {
            login(event);
        } else if (status === 304) {
            alert("Failed to create account; try another email.");
        } else {
            alert("Failed to create account.");
        }
    });
}
window.addEventListener('load', setup);