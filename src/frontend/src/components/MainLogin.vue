<template>      
      <div class="unprotected" v-if="loginError">
          <h1>
              <p>이 페이지에 대한 접근 권한이 없습니다~~~~~~</p>
          </h1>
          <h5>로그인 실패!</h5>
      </div>
      <div class="unprotected" v-else>

    <div class="wrapper">
        <div class="container">
            <h1>Welcome</h1>

            <form @submit.prevent="login()" name="form" class="form" >
                <input type="text" name="username" placeholder="Username" v-model="user">
                <input type="password" name="password" placeholder="Password" v-model="password">
                <button type="submit" id="login-button">Login</button>
            </form>
        </div>

        <ul class="bg-bubbles">
            <li></li>
            <li></li>
            <li></li>
            <li></li>
            <li></li>
            <li></li>
            <li></li>
            <li></li>
            <li></li>
            <li></li>
        </ul>
    </div>
  </div>
</template>
<script>
import axios from 'axios'

export default {
  name: 'login',  
  data () {
    return {
      loginSuccess: false,
      loginError: false,
      user: 'yhs1790@naver.com',
      password: '1234',
      error: false
    }
  },
  methods: {
    async login () {
      try {
        const result = await axios.post('/api/auth/login', {
           email: this.user,
           password: this.password
        })
        if (result.status === 200) {
          localStorage.setItem('wtw-token', result.data.replace('accessToken:', ''));          
          location.href = '/MainDiaryPage'
        }
      } catch (err) {
        this.loginError = true
        throw new Error(err)
      }
    }
  }  
}
</script>

<style scoped>
@import '../assets/css/login.css';  
</style>
