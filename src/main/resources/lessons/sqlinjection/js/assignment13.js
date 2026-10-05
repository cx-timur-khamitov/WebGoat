$(function () {
    $('.col-check').hide();
    $('#btn-admin').on('click', function () {
        if ($("#toolbar-admin").is(":visible")) {
            $("#toolbar-admin").hide();
            $(".col-check").hide();
        }
        else {
            $("#toolbar-admin").show();
            $(".col-check").show();
        }
    });

    $('#btn-online').on('click', function () {
        $('table tr').filter(':has(:checkbox:checked)').find('td').parent().removeClass().addClass('success');
        $('table tr').filter(':has(:checkbox:checked)').find('td.status').text('online');
    });
    $('#btn-offline').on('click', function () {
        $('table tr').filter(':has(:checkbox:checked)').find('td').parent().removeClass().addClass('warning');
        $('table tr').filter(':has(:checkbox:checked)').find('td.status').text('offline');
    });
    $('#btn-out-of-order').on('click', function () {
        $('table tr').filter(':has(:checkbox:checked)').find('td').parent().removeClass().addClass('danger');
        $('table tr').filter(':has(:checkbox:checked)').find('td.status').text('out of order');
    });

});

$(document).ready(function () {
    getServers('id');
});

function getServers(column) {
    $.get("SqlInjectionMitigations/servers?column=" + column, function (result, status) {
        $("#servers").empty();
        for (var i = 0; i < result.length; i++) {
            var rowStatus = "success";
            if (result[i].status === 'offline') {
                rowStatus = "danger";
            }

            // Build the row using DOM construction so that server-supplied text
            // is assigned via textContent, never interpreted as HTML markup.
            // This eliminates the DOM-XSS sink that existed when an HTML template
            // string was assembled via .replace() and fed to jQuery .append().
            var $row = $('<tr>').addClass(rowStatus);

            var $checkCell = $('<td>').addClass('col-check');
            $checkCell.append($('<input>').attr('type', 'checkbox').addClass('form-check-input'));
            $row.append($checkCell);

            $('<td>').text(result[i].hostname).appendTo($row);
            $('<td>').text(result[i].ip).appendTo($row);
            $('<td>').text(result[i].mac).appendTo($row);
            $('<td>').addClass('status').text(rowStatus).appendTo($row);
            $('<td>').text(result[i].description).appendTo($row);

            $("#servers").append($row);
        }

    });
}
