<template>
  <div class="dcontainer">
 <div class="user-profile-area">
  <div class="task-manager">emotion manager</div> 
  <div class="side-wrapper">
   <div class="user-profile">
    <img src="../assets/me.png" alt="" class="user-photo">
    <div class="user-name">윤혜수</div>
    <div class="user-mail">yhs1790@naver.com</div>
   </div>
   <div class="user-notification">
    <div class="notify">
     <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 14 14" fill="currentColor">
      <path d="M13.533 5.6h-.961a.894.894 0 01-.834-.57.906.906 0 01.197-.985l.675-.675a.466.466 0 000-.66l-1.32-1.32a.466.466 0 00-.66 0l-.676.677a.9.9 0 01-.994.191.906.906 0 01-.56-.837V.467A.467.467 0 007.933 0H6.067A.467.467 0 005.6.467v.961c0 .35-.199.68-.57.834a.902.902 0 01-.983-.195L3.37 1.39a.466.466 0 00-.66 0L1.39 2.71a.466.466 0 000 .66l.675.675c.25.25.343.63.193.995a.902.902 0 01-.834.56H.467A.467.467 0 000 6.067v1.866c0 .258.21.467.467.467h.961c.35 0 .683.202.834.57a.904.904 0 01-.197.984l-.675.676a.466.466 0 000 .66l1.32 1.32a.466.466 0 00.66 0l.68-.68a.894.894 0 01.994-.187.897.897 0 01.556.829v.961c0 .258.21.467.467.467h1.866c.258 0 .467-.21.467-.467v-.961c0-.35.202-.683.57-.834a.904.904 0 01.984.197l.676.675a.466.466 0 00.66 0l1.32-1.32a.466.466 0 000-.66l-.68-.68a.894.894 0 01-.187-.994.897.897 0 01.829-.556h.961c.258 0 .467-.21.467-.467V6.067a.467.467 0 00-.467-.467zM7 9.333C5.713 9.333 4.667 8.287 4.667 7S5.713 4.667 7 4.667 9.333 5.713 9.333 7 8.287 9.333 7 9.333z" /></svg>
    </div>
    <div class="notify alert">
     <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" fill="currentColor">
      <path d="M10.688 95.156C80.958 154.667 204.26 259.365 240.5 292.01c4.865 4.406 10.083 6.646 15.5 6.646 5.406 0 10.615-2.219 15.469-6.604 36.271-32.677 159.573-137.385 229.844-196.896 4.375-3.698 5.042-10.198 1.5-14.719C494.625 69.99 482.417 64 469.333 64H42.667c-13.083 0-25.292 5.99-33.479 16.438-3.542 4.52-2.875 11.02 1.5 14.718z" />
      <path d="M505.813 127.406a10.618 10.618 0 00-11.375 1.542C416.51 195.01 317.052 279.688 285.76 307.885c-17.563 15.854-41.938 15.854-59.542-.021-33.354-30.052-145.042-125-208.656-178.917a10.674 10.674 0 00-11.375-1.542A10.674 10.674 0 000 137.083v268.25C0 428.865 19.135 448 42.667 448h426.667C492.865 448 512 428.865 512 405.333v-268.25a10.66 10.66 0 00-6.187-9.677z" /></svg>
    </div>
    <div class="notify alert">
     <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" fill="currentColor">
      <path d="M467.812 431.851l-36.629-61.056a181.363 181.363 0 01-25.856-93.312V224c0-67.52-45.056-124.629-106.667-143.04V42.667C298.66 19.136 279.524 0 255.993 0s-42.667 19.136-42.667 42.667V80.96C151.716 99.371 106.66 156.48 106.66 224v53.483c0 32.853-8.939 65.109-25.835 93.291L44.196 431.83a10.653 10.653 0 00-.128 10.752c1.899 3.349 5.419 5.419 9.259 5.419H458.66c3.84 0 7.381-2.069 9.28-5.397 1.899-3.329 1.835-7.468-.128-10.753zM188.815 469.333C200.847 494.464 226.319 512 255.993 512s55.147-17.536 67.179-42.667H188.815z" /></svg>
    </div>
   </div>
   <div class="progress-status">12/34</div>
   <div class="progress">
    <div class="progress-bar"></div>
   </div>
   <div class="task-status">
    <div class="task-stat">
     <div class="task-number">12</div>
     <div class="task-condition">Completed</div>
     <div class="task-tasks">tasks</div>
    </div>
    <div class="task-stat">
     <div class="task-number">22</div>
     <div class="task-condition">To do</div>
     <div class="task-tasks">tasks</div>
    </div>
    <div class="task-stat">
     <div class="task-number">243</div>
     <div class="task-condition">All</div>
     <div class="task-tasks">completed</div>
    </div>
   </div>
  </div>
  <div class="side-wrapper">
   <div class="project-title">Emotion</div>
   <div class="project-name">
    <div class="project-department">보통(약간우울)</div>
    <div class="project-department">우울</div>
    <div class="project-department">보통(약간낙관)</div>
    <div class="project-department">다혈질</div>
   </div>
  </div> 
 </div>
 <div class="main-area">
  <div class="header">
   <div class="search-bar">
    <input type="text" placeholder="Search...">
   </div>
   <div class="inbox-calendar">
    <input type="checkbox" class="inbox-calendar-checkbox">
    <div class="toggle-page">
     <span>Diary</span>
    </div>
    <div class="layer"></div>
   </div>
   <div class="color-menu">
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 464.7 464.7"><path d="M446.6 18.1a62 62 0 00-87.6 0L342.3 35a23 23 0 10-32.5 32.5l5.4 5.4-180.6 180.6L71.9 316c-5 5-8 11.6-8.2 18.7l-.2 3.3-2.5 56.7a9.4 9.4 0 009.4 9.8h.4l30-1.3 18.4-.8 8.3-.4a37 37 0 0024.5-10.8l240.9-240.9 4.5 4.6a23 23 0 0032.5 0c9-9 9-23.6 0-32.6l16.7-16.7a62 62 0 000-87.6zm-174 209.2l-84.6 16 138-138 34.4 34.3-87.8 87.7zM64.5 423.9C28.9 423.9 0 433 0 444.3c0 11.3 28.9 20.4 64.5 20.4s64.5-9.1 64.5-20.4C129 433 100 424 64.5 424z"/></svg>
   </div>
  </div>
  <div class="main-container">
   <div class="inbox-container">
    <div class="inbox">
     <div id="deplight" class="msg msg-department anim-y deplight">
      보통(약간우울)
      <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 492 492" style="display:none;">
       <path d="M484.13 124.99l-16.11-16.23a26.72 26.72 0 00-19.04-7.86c-7.2 0-13.96 2.79-19.03 7.86L246.1 292.6 62.06 108.55c-5.07-5.06-11.82-7.85-19.03-7.85s-13.97 2.79-19.04 7.85L7.87 124.68a26.94 26.94 0 000 38.06l219.14 219.93c5.06 5.06 11.81 8.63 19.08 8.63h.09c7.2 0 13.96-3.57 19.02-8.63l218.93-219.33A27.18 27.18 0 00492 144.1c0-7.2-2.8-14.06-7.87-19.12z"></path>
      </svg>
     </div>
     <div id="dep" class="msg msg-department anim-y dep none">
     우울
     <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 492 492" style="display:none;">
       <path d="M484.13 124.99l-16.11-16.23a26.72 26.72 0 00-19.04-7.86c-7.2 0-13.96 2.79-19.03 7.86L246.1 292.6 62.06 108.55c-5.07-5.06-11.82-7.85-19.03-7.85s-13.97 2.79-19.04 7.85L7.87 124.68a26.94 26.94 0 000 38.06l219.14 219.93c5.06 5.06 11.81 8.63 19.08 8.63h.09c7.2 0 13.96-3.57 19.02-8.63l218.93-219.33A27.18 27.18 0 00492 144.1c0-7.2-2.8-14.06-7.87-19.12z"></path>
      </svg>
     </div>
     <div id="normal" class="msg msg-department anim-y normal none">
     보통(약간낙관)
     <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 492 492" style="display:none;">
       <path d="M484.13 124.99l-16.11-16.23a26.72 26.72 0 00-19.04-7.86c-7.2 0-13.96 2.79-19.03 7.86L246.1 292.6 62.06 108.55c-5.07-5.06-11.82-7.85-19.03-7.85s-13.97 2.79-19.04 7.85L7.87 124.68a26.94 26.94 0 000 38.06l219.14 219.93c5.06 5.06 11.81 8.63 19.08 8.63h.09c7.2 0 13.96-3.57 19.02-8.63l218.93-219.33A27.18 27.18 0 00492 144.1c0-7.2-2.8-14.06-7.87-19.12z"></path>
      </svg>
     </div>
     <div id="angry" class="msg msg-department anim-y angry none">
     다혈질
     <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 492 492" style="display:none;">
       <path d="M484.13 124.99l-16.11-16.23a26.72 26.72 0 00-19.04-7.86c-7.2 0-13.96 2.79-19.03 7.86L246.1 292.6 62.06 108.55c-5.07-5.06-11.82-7.85-19.03-7.85s-13.97 2.79-19.04 7.85L7.87 124.68a26.94 26.94 0 000 38.06l219.14 219.93c5.06 5.06 11.81 8.63 19.08 8.63h.09c7.2 0 13.96-3.57 19.02-8.63l218.93-219.33A27.18 27.18 0 00492 144.1c0-7.2-2.8-14.06-7.87-19.12z"></path>
      </svg>
     </div>
     
     <div id="loopdata"></div>        

    </div>
    <div class="add-task">
     <button class="add-button">Add task</button>
    </div>
   </div>
   <div class="mail-detail">
    <div class="mail-detail-header">
     <div class="mail-detail-profile">
      <img src="../assets/me.png" alt="" class="members inbox-detail" />
      <div class="mail-detail-name">윤혜수</div>
     </div>
     <div class="mail-icons" @click="write"> 
      <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-paperclip">
       <path d="M21.44 11.05l-9.19 9.19a6 6 0 01-8.49-8.49l9.19-9.19a4 4 0 015.66 5.66l-9.2 9.19a2 2 0 01-2.83-2.83l8.49-8.48" /></svg>
     </div>
    </div>
    <div class="mail-contents">
     <div class="mail-contents-subject">
      <input type="checkbox" name="msg" id="mail20" class="mail-choice" checked disabled>
      <label for="mail20"></label>      
      <div class="mail-contents-title"><input type="text" name="title" style="font-size: 17px;" readonly></div>
     </div>
     <div class="mail">
      <div class="mail-time">
       <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-clock">
        <circle cx="12" cy="12" r="10" />
        <path d="M12 6v6l4 2" /></svg>
        <span id="date">{{date}}</span>
      </div>
      <div class="mail-inside">
          <article>
          <section>
            <textarea spellcheck=false name="contents" readonly></textarea>
            <div class="textarea-clone"></div>
          </section>   
        </article>
      </div>
     </div>
    </div>
    <div class="mail-textarea">
     <input type="text" placeholder="Write a comment...">
     <div class="textarea-icons">
      <div class="attach">
       <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-paperclip">
        <path d="M21.44 11.05l-9.19 9.19a6 6 0 01-8.49-8.49l9.19-9.19a4 4 0 015.66 5.66l-9.2 9.19a2 2 0 01-2.83-2.83l8.49-8.48" /></svg>
      </div>
      <div class="send" @click="save">
       <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-send">
        <path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z" /></svg>
      </div>
     </div>
    </div>
   </div>
   <div class="calendar-container">
    <div class="calender-tab anim-y">
     <div class="week-month">
      <button class=" button active">Week</button>
      <button class=" button button-month">Month</button>
     </div>
     <div class="month-change">
      <div class="current-month">October</div>
      <div class="current-year">2020</div>
     </div>
     <div class="week-month">
      <button class=" button button-weekends">Weekends</button>
      <button class=" button button-task active">Add task</button>
     </div>
    </div>
    <div class="calendar-wrapper anim-y">
     <div class="calendar">
      <div class="days">Monday</div>
      <div class="days">Tuesday</div>
      <div class="days">Wednesday</div>
      <div class="days">Thursday</div>
      <div class="days">Friday</div>
      <div class="days">Saturday</div>
      <div class="days">Sunday</div>
      <div class="day not-work">31</div>
      <div class="day project-market">1
       <div class="hover-title">Marketing</div>
       <div class="project-detail">Sales report from last month</div>
       <div class="project-detail">Prepare offers for clients</div>
       <div class="popup-check">
         <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-check-square"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/>
        </svg>
       </div>
      </div>
      <div class="day">2</div>
      <div class="day project-design">3
       <div class="project-detail design">Create 3 illustrations for blog post about design trends</div>
      </div>
      <div class="day">4</div>
      <div class="day">5</div>
      <div class="day">6</div>
      <div class="day project-develop">7
       <div class="project-detail develop">Take part in course about future design trends and new technologies</div>
      </div>
      <div class="day">8</div>
      <div class="day">9</div>
      <div class="day">10</div>
      <div class="day">11</div>
      <div class="day">12</div>
      <div class="day">13</div>
      <div class="day">14</div>
      <div class="day project-market">15
       <div class="hover-title">Marketing</div>
       <div class="project-detail">Write an article about design trends</div>
       <div class="popup-check">
         <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-check-square"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/>
        </svg>
       </div>
      </div>
      <div class="day">16</div>
      <div class="day project-market">17
       <div class="hover-title">Marketing</div>
       <div class="project-detail">Create AdWords campaign</div>
       <div class="project-detail">Send newsletter to clients</div>
       <div class="popup-check">
         <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-check-square"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/>
        </svg>
       </div>
      </div>
      <div class="day">18</div>
      <div class="day">19</div>
      <div class="day">20</div>
      <div class="day">21</div>
      <div class="day">22</div>
       <div class="day project-finance">23
        <div class="hover-title">Management</div>
       <div class="project-detail finance">Redesign project ui interface for clients and get feedback</div>
       <div class="popup-check">
         <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-check-square"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/>
        </svg>
       </div>
      </div>
      <div class="day">24</div>
      <div class="day">25</div>
      <div class="day">26</div>
      <div class="day">27</div>
      <div class="day">28</div>
      <div class="day">29</div>
      <div class="day">30</div>
      <div class="day not-work">1</div>
      <div class="day not-work">2</div>
      <div class="day not-work">3</div>
      <div class="day not-work">4</div>
     </div>
    </div>
   </div>
  </div>
 </div>
</div>
</template>

<script>     
const moment = require('moment'); 

  export default {
    data() {
      return {         
        date: moment(new Date()).format('DD MMM, YYYY'),
        count: 0,
        emcd: 'EM04',
        now: moment().diff(moment(new Date()).format('YYYY-01-01'),"days"),
        token: 'Bearer:' + localStorage.getItem('wtw-token')
      }
    },
    methods: {      
    add: function() {
    
      let contents = document.getElementsByName("contents")[0].value;
      let title = document.getElementsByName("title")[0].value;

      if(contents==='' || title==='') {
        alert('값이 비었다... ');
        return;
      }

      return new Promise((resolve) => { 
        fetch('http://localhost:8080/api/add', {
        method: 'post', 
        headers: {
        'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          contents: contents,
          title: title,
          emotion_cd: this.emcd
          })
        })
        .then(res => resolve(res.json())) 
      })    
    },
    save: function() {     
      this.add().then(function(data) {
        
          if(data === '')
          { 
            alert(data.message); 
            return;
          }        
          else
          {          
            location.href = '/em'; 
          }
          
      }) 
    },
    list: function() {  

      fetch('http://localhost:8080/api/list', {
        // fetch('http://localhost:8080/api/test', {
        method: 'get', 
        headers: {
         'Content-Type': 'application/json',
         'Authorization': this.token
        } 
        })
        .then(res => res.json())
        .then(function(data) { 
          let datahtml = '' 
          if(data !== '')
          {  
            for (let i in data) { 
              datahtml = datahtml + '<div class="msg selected-bg anim-y" onclick="showcontent(this)">' +
              '<input type="checkbox" name="msg" id="mail3" class="mail-choice ' + data[i].emotionCd + '" checked disabled><label for="mail3"></label>' +
              '<div class="msg-content">' +  
              '<div class="msg-title">' + data[i].title + '<span id="msgno" style="display:none;">' + data[i].uuid + '</span>'+ 
              '</div><div class="msg-date">' + moment(String(data[i].date[0]) + String(data[i].date[1])+ String(data[i].date[2])).format('DD MMM, YYYY') + 
              '</div></div><img src="../img/me.png" alt="" class="members mail-members"></div>'  
            }          
          } 
            document.getElementById('loopdata').innerHTML = datahtml; 
            
          } 
        )
    },
    listCount: function() { 
      this.searchdiary('EM01').then(function(data) { 
          document.querySelector('.task-number.deplight').textContent = data.length; 
      })
      
      this.searchdiary('EM02').then(function(data) { 
          document.querySelector('.task-number.normal').textContent = data.length; 
      })

      this.searchdiary('EM03').then(function(data) { 
          document.querySelector('.task-number.angry').textContent = data.length; 
      })

      this.searchdiary('EM04').then(function(data) { 
          document.querySelector('.task-number.dep').textContent = data.length; 
      })

      // 일단 주석 1 
      // document.styleSheets[0].cssRules[25].cssRules[1].style.cssText = 'width:' + ((this.now / 365) * 100) + '%;';
      // document.getElementsByClassName('progress-bar')[0].setAttribute('style', 'width:' + ((this.now / 365) * 100) + '%;');
      
    },
    write: function() {    
      document.getElementsByName("title")[0].disabled = false;
      document.getElementsByName("contents")[0].disabled = false;
      document.getElementsByName("title")[0].value = '';
      document.getElementsByName("contents")[0].value = '';
    },
    changeEm: function() {     

      if( document.getElementsByName("title")[0].disabled ) 
      {
        return;
      }

      const mail20 = document.querySelector('#mail20');
      
      mail20.className = 'mail-choice';        
      this.count += 1; 

      if(this.count == 1) {
        mail20.classList.add('EM01');   
        this.emcd = 'EM01';
        document.querySelector('.mail-contents-subject').title = '보통(약간우울)';

      } else if(this.count == 2) {
        mail20.classList.add('EM02');    
        this.emcd = 'EM02';
        document.querySelector('.mail-contents-subject').title = '보통(약간낙관)';
      
      } else if(this.count == 3) {
        mail20.classList.add('EM03');    
        this.emcd = 'EM03';
        document.querySelector('.mail-contents-subject').title = '다혈질';
      
      } else {
        mail20.classList.add('EM04');    
        this.emcd = 'EM04';
        document.querySelector('.mail-contents-subject').title = '우울';
        this.count = 0; 
      }
      
    },
    searchdiary: function(obj) { 
      return new Promise((resolve) => { 
        fetch('http://localhost:8080/api/listbyemcd/' + obj, {
        method: 'get', 
        headers: {
        'Content-Type': 'application/json'
        }
        })
        .then(res => resolve(res.json())) 
      })    
    },
    searchbar: function(obj) {

      let value, name, item, i;

      value = document.getElementById("value").value.toUpperCase();
      item  = document.getElementsByClassName("selected-bg");

      for(i=0; i<item.length; i++) {
        name = item[i].getElementsByClassName("msg-title");
      
        if(name[0].innerHTML.toUpperCase().indexOf(value) > -1){
          item[i].style.display = "flex";

        }else{
          item[i].style.display = "none";
        }
      }

     }
    },
    mounted() {  
     this.list(); 
    //  this.listCount();
   }
  }
  

</script>
<style scoped>   
@import '../assets/css/em.css';
</style>