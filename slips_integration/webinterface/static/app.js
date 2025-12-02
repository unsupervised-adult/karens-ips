// SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
//SPDX-License-Identifier: GPL-2.0-only
// import { update } from './analysis.js';
import {update} from '../analysis/analysis/static/js/analysis.js';


const headers2 = {
    headers: { 'Content-Type': 'application/json' }
}

function round(value, precision) {
    var multiplier = Math.pow(10, precision || 0);
    return Math.round(value * multiplier) / multiplier;
}
function calcDur(analysis_start, analysis_end){
    /*
        Calcuialte duration in seconds
    */
    let start = new Date(analysis_start)
    let end = new Date(analysis_end)
    return round((Date.parse(end)- Date.parse(start)) / 60000, 1).toString() + "s"
}
function fetchDetailedInfo() {
    fetch("/info", {
        method: "GET",
        headers: headers2
    }).then(response => response.json())
        .then(data => {
            document.getElementById("num_profiles").textContent = data['num_profiles'];
            document.getElementById("num_alerts").textContent = data['num_alerts'];
            document.getElementById("dur").textContent = calcDur(data['analysis_start'], data['analysis_end']);
        });
}

function initializeWidgetsAndListeners() {
    $("#table_choose_redis").DataTable({
        destroy: true,
        searching: false,
        ajax: '/redis',
        "bInfo": false,
        scrollY: "15vh",
        paging: false,
        select: true,
        columns: [
            { data: 'filename' },
            { data: 'redis_port' }
        ]
    })
    $('#reload_button').click(function(){
        update();
    })

    const modalElement = document.getElementById('modal_choose_redis');
    const bsModal = new bootstrap.Modal(modalElement, {
        backdrop: 'static',
        keyboard: false
    });

    modalElement.addEventListener('show.bs.modal', function (e) {
        $('#table_choose_redis').DataTable().ajax.reload();
    })

    $('#button_choose_db').click(function () {
        let chosen_db = $('#table_choose_redis').DataTable().row({ selected: true }).data()
        bsModal.hide();
        let link = "/db/" + chosen_db['redis_port']
        $.get(link);
        window.location.reload();
    });

}

function fetchDataDB() {
    fetch("/info", {
        method: "GET",
        headers: headers2
    }).then(response => response.json())
        .then(data => {
            document.getElementById("changedb_button").innerHTML = '<i class="fa fa-database"></i> ' + data['name'];
        });
}

function initPage() {
    initializeWidgetsAndListeners();
    fetchDataDB();
    fetchDetailedInfo();
}
$(document).ready(function () {
    initPage();
});
