# Reproduce Large schemas generate huge index.d.ts causing slow autocomplete and type-checking in your editor

This repository attempts to reproduce the problems discussed in this [github issue](https://github.com/prisma/prisma/issues/4807)

## Getting started

### 1. Clone the repository and run npm install to install the dependencies

Clone this repository:

```
git clone https://github.com/ludralph/reproduction-schema.git
```

Install npm dependencies:

```
cd reproduction-schema
npm install
```

### 2. Create the database

create a .env file at the root and add an environment variable `DB_URL`
The value of `DB_URL` will be your database connection string
For example: DB_URL=postgresql://username:password@localhost:5432/postgres


### 3. Generate the Prisma Client

Execute with this command: 

```
npx prisma generate
```

## Testing for slow autocomplete and typechecking
1. Open `script.ts` file  and test for slow autocomplete when trying to create a  script
2. Open node_module/.prisma/client/index.d.ts to observe how long it takes the generated file to load in the IDE



