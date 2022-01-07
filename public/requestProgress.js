const submitButton = document.getElementById('submit');
        
submitButton.addEventListener('click', function(a) {
  a.preventDefault();//prevent from reloading

  let data = {
    "ok": true
  };
  const id = 0; //doesn't have a way to get this currently? should be ID of currently viewed request. This isn't my section though so I'm going to prioritize other stuff over getting this implemented
  fetch(`/markProgress/${id}`, {

    method: 'put', 
    cache: 'no-cache', 
    credentials: 'same-origin', 
    headers: {
      'Content-Type': 'application/json'
    },
    redirect: 'follow', 
    referrerPolicy: 'no-referrer', 
    body: JSON.stringify(data) // body data type must match "Content-Type" header
  }).then(function(response) {
    return response.text();
  }).then(function(text) {
    console.log(text); //again should really output to HTML; not my division so I'm prioritizing other stuff
  }).catch(function(error) {
    console.error(error);
  })
});
        