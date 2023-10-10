import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

// A `main` function so that we can use async/await
async function main() {
  await prisma.coupon.create({
    data:{
      code: 'TEST',
      dateRedeemed: new Date(),
      userPropertiesToUpdate: {
        name: 'TEST'
      }

    }
  })
}

main()
  .then(async () => {
    await prisma.$disconnect()
  })
  .catch(async (e) => {
    console.error(e)
    await prisma.$disconnect()
    process.exit(1)
  })
