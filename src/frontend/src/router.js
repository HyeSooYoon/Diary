import { createWebHistory, createRouter } from 'vue-router';
import MainLogin from '@/components/MainLogin.vue'
import MainDiaryPage from '@/components/MainDiaryPage.vue'
import HelloWorld from '@/components/HelloWorld.vue'

const routes = [
  { path: '/login', name: 'MainLogin', component: MainLogin,   beforeEnter: function (to, from, next) { next() } },
  { path: '/MainDiaryPage', name: 'MainDiaryPage', component: MainDiaryPage,   beforeEnter: function (to, from, next) { next() } },
  { path: '/HelloWorld', name: 'HelloWorld', component: HelloWorld,   beforeEnter: function (to, from, next) { next() } }
]

export const router = createRouter({
  history: createWebHistory(),
  routes,
});