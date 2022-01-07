function setup() {
    async function getDefaults() {
        const email = window.localStorage.getItem('user_email');
        if (email !== null) {
            let status = 0;
            fetch(`/user/data/?target_email=${email}`, {
                method: "GET",
                cache: "no-cache",
                headers: {
                    "Content-Type": "application/json"
                },
            }).then((response) => {
                status = response.status;
                if (status === 404) {
                    return {}
                }
                return response.json();
            }).then((data) => {
                if (status === 200) {
                    document.getElementById('name').value = data['display_name'];
                    document.getElementById('email').textContent = `Current user: ${data['email']}`;
                    document.getElementById('phoneNumber').value = data['phone_number'];
                }
            });
        }
    }
    getDefaults();
    document.getElementById("updateButton").addEventListener("click", updateDetails);
    document.getElementById("deleteButton").addEventListener("click", deleteAccount);
}
async function updateDetails(event) {
    event.preventDefault();
    const email = window.localStorage.getItem('user_email');
    const displayName = document.getElementById("name").value;
    const phoneNumber = document.getElementById("phoneNumber").value;
    const data = {"user_email":email, "display_name":displayName, "phone_number":phoneNumber};
    fetch("/user/edit",{
        method: "PUT",
        cache: "no-cache",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    }).then((response) => {
        return response.status;
    }).then((status) => {
        if (status === 204) {
            alert("Updated!");
        } else if (status === 403) {
            alert("Invalid login session.");
        } else {
            alert("Failed to edit account.");
        }
    });
}
async function deleteAccount(event) {
    event.preventDefault();
    const email = window.localStorage.getItem('user_email');
    const confirmation = window.confirm("Are you sure you'd like to delete your account? Click OK to confirm.");
    if (confirmation) {
        const data = {"user_email":email}; //Maybe add a password requirement? Already logged in so would mostly just be another way to verify. For now sticking with this way
        fetch("/user/delete",{
            method: "DELETE",
            cache: "no-cache",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(data)
        }).then((response) => {
            return response.status;
        }).then((status) => {
            if (status === 204) {
                alert("Deleted!");
                window.location.href = "./user/logout";
            } else if (status === 403) {
                alert("Invalid login session.");
            // } else if (status === 409) {
            //     alert("Failed to delete account; please first close all of your active requests.")
            } else {
                alert("Failed to delete account.");
            }
        });
    }
}
window.addEventListener('load', setup);