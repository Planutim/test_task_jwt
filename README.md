# test_task_jwt


Rename your __.env.example__ to __.env__ and set environmental variables




### Routes
* __POST /token__  	- 	Get new pair of tokens
	*	id = (uuid)
* __POST /token/refresh__ 	- 	Refresh old pair of tokens
	*	id = (uuid)
    *	access_token = (jwt string)
    *	refresh_token = base64(jwt string)
