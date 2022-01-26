const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');


const userSchema = mongoose.Schema({
    name: {
        type: String,
        maxlength: 50
    },
    email: {
        type: String,
        trim: true,
        unique: 1
    },
    password: {
        type: String,
        minlength: 5
    },
    lastname: {
        type: String,
        maxlength: 50
    },
    role: {
        type: Number,
        default: 0
    },
    image: String,
    token: {
        type: String
    },
    tokenExp: {
        type: Number
    }
});

userSchema.pre('save', function(next) {
    var user = this;

    if(user.isModified('password')) {
        // 비밀번호를 암호화 시킨다.
        bcrypt.genSalt(saltRounds, (err, salt) => {
            if(err) return next(err);
    
            bcrypt.hash( user.password, salt, (err, hash) => {
                // Store hash in your password DB.
                if(err) return next(err);
    
                user.password = hash;
                next();
            });
        });
    } else {
        next();
    }
})

userSchema.methods.comparePassword = function(plainPassword, callbackfunc) {
    // 암호화된 비밀번호로 비교
    bcrypt.compare(plainPassword, this.password, (err, isMatch) => {
        if(err) return callbackfunc(err);
        callbackfunc(null, isMatch);
    })
}

userSchema.methods.generateToken = function(cb) {
    var user = this;

    var token = jwt.sign(user._id.toHexString(), 'secretToken');
    
    user.token = token
    user.save((err, user) => {
        if(err) return cb(err);
        cb(null, user)
    })

}

userSchema.methods.findByToken = function(token, cb) {
    var user = this;

    //토큰을 decode한다.
    jwt.verify(token, 'secretToken', function(err, decoded) {
        //유저 아이디를 이용해서 유저를 찾은 다음에
        //클라이언트에서 가져온 token과 DB에 보관된 토큰이 일치하는지 확인

        user.findOne({"_id":decoded, "token":token}, function(err, user) {
            if(err) return cb(err);
            cb(null, user)
        })
    });
}


const User = mongoose.model('User', userSchema);

module.exports = {User};
