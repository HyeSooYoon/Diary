<template>
 <div>
   <router-view/>
 </div>
</template>

<script>
// import request from "request"
export default {
  name: 'App',
  mounted() {
    // Proxy 서버 요청 확인 테스트.
    // request('http://localhost:8080/api/hello', function(error, response, body) {
    //   window.console.log('error', error);
    //   window.console.log('statusCode', response && response.statusCode);
    //   window.console.log('body', body);

    // }); 
    }
  }
</script>

\