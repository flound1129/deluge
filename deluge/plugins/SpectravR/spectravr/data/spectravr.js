/**
 * spectravr.js — SpectraVR preferences panel for the Deluge web UI.
 *
 * Adds a "SpectraVR" page to Preferences showing the API token.
 * "Reveal" fetches the token from /spectravr/admin/token (Deluge session auth).
 * Subsequent clicks copy the token to the clipboard.
 */

Ext.ns('Deluge.ux.preferences');

Deluge.ux.preferences.SpectravRPage = Ext.extend(Ext.Panel, {
    title: _('SpectraVR'),
    layout: 'fit',
    border: false,

    initComponent: function () {
        Deluge.ux.preferences.SpectravRPage.superclass.initComponent.call(this);

        var fs = this.add({
            xtype: 'fieldset',
            border: false,
            title: _('API Token'),
            autoHeight: true,
            labelWidth: 60,
        });

        this.tokenField = fs.add({
            xtype: 'textfield',
            fieldLabel: _('Token'),
            width: 380,
            readOnly: true,
            value: '',
            emptyText: _('(click Reveal to show)'),
        });

        this.actionBtn = fs.add({
            xtype: 'button',
            text: _('Reveal'),
            style: 'margin-top: 8px',
            handler: this.onAction,
            scope: this,
        });
    },

    onAction: function () {
        var token = this.tokenField.getValue();

        if (token) {
            // Token already revealed — copy it.
            this._copyToken(token);
            return;
        }

        // First click: fetch token from the daemon.
        Ext.Ajax.request({
            url: '/spectravr/admin/token',
            method: 'GET',
            success: function (response) {
                try {
                    var data = Ext.decode(response.responseText);
                    if (data.token) {
                        this.tokenField.setValue(data.token);
                        this.actionBtn.setText(_('Copy'));
                    } else {
                        Ext.Msg.alert(_('SpectraVR'), _('Token not set. Check spectravr.conf.'));
                    }
                } catch (e) {
                    Ext.Msg.alert(_('SpectraVR'), _('Unexpected response from server.'));
                }
            },
            failure: function () {
                Ext.Msg.alert(_('SpectraVR'), _('Failed to retrieve token. Are you logged in?'));
            },
            scope: this,
        });
    },

    _copyToken: function (token) {
        if (window.navigator && navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(token).then(function () {
                Ext.Msg.alert(_('SpectraVR'), _('Token copied to clipboard.'));
            }).catch(function () {
                this._fallbackCopy(token);
            }.bind(this));
        } else {
            this._fallbackCopy(token);
        }
    },

    _fallbackCopy: function (token) {
        // Select the text field so the user can copy manually.
        var el = this.tokenField.el.dom;
        el.select();
        try {
            document.execCommand('copy');
            Ext.Msg.alert(_('SpectraVR'), _('Token copied to clipboard.'));
        } catch (e) {
            Ext.Msg.alert(_('SpectraVR'), _('Copy failed — please select and copy the token manually.'));
        }
    },
});

Ext.ns('Deluge.plugins');

Deluge.plugins.SpectravRPlugin = Ext.extend(Deluge.Plugin, {
    name: 'SpectravR',

    onEnable: function () {
        this.prefsPage = deluge.preferences.addPage(
            new Deluge.ux.preferences.SpectravRPage()
        );
    },

    onDisable: function () {
        deluge.preferences.removePage(this.prefsPage);
    },
});

Deluge.registerPlugin('SpectravR', Deluge.plugins.SpectravRPlugin);
