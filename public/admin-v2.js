const API = location.origin;
const hours = Array.from({length:24}, (_,i)=>String(i).padStart(2,"0")+":00");

function $(id){return document.getElementById(id)}

function today(){
 const d = new Date();
 return d.getFullYear()+"-"+String(d.getMonth()+1).padStart(2,"0")+"-"+String(d.getDate()).padStart(2,"0");
}

function headers(){
 return {
   "Content-Type":"application/json",
   "x-fenix-admin": $("adminUser").value.trim(),
   "x-fenix-admin-secret": $("adminSecret").value.trim()
 };
}

async function apiGet(url){
 const r = await fetch(API+url,{headers:headers()});
 return await r.json();
}

function draw(schedule){
 const date = $("slotDate").value;
 $("rows").innerHTML = hours.map(hour=>{
   const slot = schedule.find(s=>s.slotDate===date && s.slotHour===hour) || {};
   return `
   <div class="row">
     <div>${hour}</div>
     <input value="${slot.screen1Name||""}">
     <input value="${slot.screen2Name||""}">
     <input value="${slot.screen3Name||""}">
     <button>Salvar</button>
   </div>`;
 }).join("");
}

async function loadSchedule(){
 $("msg").textContent="Carregando...";
 const date = $("slotDate").value;
 const data = await apiGet("/api/fenix/admin/schedule?slotDate="+date);
 draw(data.schedule || []);
 $("msg").textContent="Grade carregada";
}

window.onload=()=>{
 $("slotDate").value=today();
 $("saveLogin").onclick=()=>{$("loginMsg").textContent="Login salvo";};
 $("loadSchedule").onclick=loadSchedule;
};
