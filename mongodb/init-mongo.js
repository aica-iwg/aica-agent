db.createUser(
    {
        user : "aica_admin",
        pwd  : "BeerB0ttle13!",
        roles : [
            {
                role : "readWrite",
                db : "aica_db"
            }
        ]
    }
)