const express = require('express')
const contacts = require('../../controllers/contacts/contacts.js')
const router = express.Router()



router.get('/', contacts.listContacts)

router.get('/:contactId', contacts.getContactById)

router.post('/', contacts.addContact)

router.put('/:contactId', contacts.updateContact)

router.patch('/:contactId/favorite', contacts.updateContactFavorite)

router.delete('/:contactId', contacts.removeContact)



module.exports = router

// mongodb+srv://TEST_USER:Test_User@db-contacts.hmcyp.mongodb.net/?retryWrites=true&w=majority&appName=db-contacts