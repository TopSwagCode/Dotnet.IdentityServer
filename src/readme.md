

# TODO

* Add gitignore and remember to keep out DevCerts, Database stuff and other assets
* Add missing services to docker-compose
* Stable storage MS SQL and Postgres with backups. (Branch for postgres)
* RabbitMQ or something like it for adding more services
* Adding some micro services and clients
* Cleanup for deploy to public repository
* Share links to all resources
* Make database migrations in some smart way. Part of container?
* Host sample project somewhere.
* Fix cors for inside docker
* Fic connection string to work inside and outside docker
* Add some best practices nuget packages eg Serilog
* Add basic Elastic logging? <-- low prioty. Not version 1.
* Add simple database to API
* Have 2 API's that only work for certain clients. Eg Admin API, Client API.
* Add roles, and other security stuff for admin users, normal users
* Add more 3rd party login providers and make sure we have proper endpoints to handle privarchy and retrive user data
* Cleanup in design and make it look like 1 product
* Add user signup
* Add Admin pages
* Fix DiagnosticsController endpoint. Only works for localhost hardcoded!
* Create new Youtube video for repository



https://docs.microsoft.com/en-us/aspnet/core/security/docker-compose-https?view=aspnetcore-5.0

https://docs.microsoft.com/en-us/aspnet/core/security/docker-https?view=aspnetcore-5.0

https://docs.docker.com/engine/examples/dotnetcore/

https://github.com/IdentityServer/IdentityServer4/tree/main/samples/Clients/src

https://expressdb.io/sql-server-express-feature-comparison.html#sql-server-edition-feature-comparison

https://hub.docker.com/_/microsoft-mssql-server

docker run -e 'ACCEPT_EULA=Y' -e 'SA_PASSWORD=yourStrong(!)Password' -e 'MSSQL_PID=Express' -p 1433:1433 -d mcr.microsoft.com/mssql/server:2017-latest-ubuntu

https://docs.docker.com/compose/aspnet-mssql-compose/


script:
```bash
#!/bin/bash

set -e
run_cmd="dotnet run --server.urls http://*:80"

until dotnet ef database update; do
>&2 echo "SQL Server is starting up"
sleep 1
done

>&2 echo "SQL Server is up - executing command"
exec $run_cmd
```

dockerfile with entry point that uses migrations:

```dockerfile
FROM microsoft/dotnet:2.1-sdk
COPY . /app
WORKDIR /app
RUN ["dotnet", "restore"]
RUN ["dotnet", "build"]
EXPOSE 80/tcp
RUN chmod +x ./entrypoint.sh
CMD /bin/bash ./entrypoint.sh
```

remember to add hostnames to your system, otherwise Authority will not be found and ignored!
This is only needed if your not running javascript!

eg:
127.0.0.1 Identity

I would add all the other services too!

Try to implement HTTPS again with docker compose. The issue seems to be Authority was not "hardcoded" to work in and outside docker.
Docker doesn't use 500X/600X ports, but the internal ports 80/443 with http(s). Might have been the issue.
Implement the different clients and API's

Fix MVC project to redirect probaly to Identity and API

Idea:
Use same ports inside docker and outside docker for easier manage ports and configurations!!!! will fix alot!