
const sendMsg = document.getElementById('send');
const getMsg = document.getElementById('get');
    
          sendMsg.addEventListener('click', function(a) {
            a.preventDefault();
    
            const commentResponse = document.getElementById('commentResponse');
            const requestId = document.getElementById('requestId');
            const commentId = document.getElementById('commentId');
            
            
    
            let data = {
              "commentResponse" : commentResponse.value,
              "requestId" : requestId.value,
              "commentId" : commentId.value,
            };
    
            fetch('/comment', {
    
              method: 'post', 
              cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
              credentials: 'same-origin', // include, *same-origin, omit
              headers: {
                'Content-Type': 'application/json'
                // 'Content-Type': 'application/x-www-form-urlencoded',
              },
              redirect: 'follow', // manual, *follow, error
              referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
              body: JSON.stringify(data) // body data type must match "Content-Type" header
            }).then(function(response) {
              return response.text();
            }).then(function(text) {
              alert(text);
              window.location.href="status.html";//jump to next page
            }).catch(function(error) {
              console.error(error);
            })
          });



          getMsg.addEventListener('click', function(a) {
            a.preventDefault();
            const requestId = document.getElementById('requestId');
            const all = document.getElementById('all');
            
            
    
            let data = {
              "requestId" : requestId.value,
              "all" : all.value,
            };
    
            fetch('/comment', {
    
              method: 'post', 
              cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
              credentials: 'same-origin', // include, *same-origin, omit
              headers: {
                'Content-Type': 'application/json'
                // 'Content-Type': 'application/x-www-form-urlencoded',
              },
              redirect: 'follow', // manual, *follow, error
              referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
              body: JSON.stringify(data) // body data type must match "Content-Type" header
            }).then(function(response) {
              return response.text();
            }).then(function(text) {
              alert(text);
              window.location.href="status.html";//jump to next page
            }).catch(function(error) {
              console.error(error);
            })
          });

